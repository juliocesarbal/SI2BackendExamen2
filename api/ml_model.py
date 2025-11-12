"""
Machine Learning module for sales prediction using Random Forest Regressor
"""
import os
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
from django.db.models import Sum, Count, Avg
from django.conf import settings
from .models import Orden, OrdenItem, Producto, Categoria, ModelMetrics, SalesPrediction


# Directory to store ML models
MODEL_DIR = os.path.join(settings.BASE_DIR, 'ml_models')
os.makedirs(MODEL_DIR, exist_ok=True)


def prepare_sales_data():
    """
    Extract and prepare sales data from database for training
    Returns a pandas DataFrame with features and target variable
    """
    # Get all completed orders with their items
    orders = Orden.objects.filter(estado='COMPLETADO').select_related('user').prefetch_related('items__producto__categoria')

    if orders.count() < 10:
        raise ValueError("Not enough sales data. Need at least 10 completed orders to train the model.")

    data = []
    for orden in orders:
        for item in orden.items.all():
            data.append({
                'fecha': orden.created_at.date(),
                'año': orden.created_at.year,
                'mes': orden.created_at.month,
                'dia_semana': orden.created_at.weekday(),  # 0=Monday, 6=Sunday
                'dia_mes': orden.created_at.day,
                'categoria_id': item.producto.categoria.id if item.producto.categoria else 0,
                'categoria_nombre': item.producto.categoria.nombre if item.producto.categoria else 'Sin categoría',
                'producto_id': item.producto.id,
                'producto_nombre': item.producto.nombre,
                'precio_unitario': float(item.precio_unitario),
                'cantidad': item.cantidad,
                'subtotal': float(item.subtotal),
            })

    df = pd.DataFrame(data)

    # Aggregate by date and category to predict daily sales per category
    df_agg = df.groupby(['fecha', 'año', 'mes', 'dia_semana', 'dia_mes', 'categoria_id', 'categoria_nombre']).agg({
        'cantidad': 'sum',
        'subtotal': 'sum',
        'producto_id': 'count'  # Number of different products sold
    }).reset_index()

    df_agg.rename(columns={'producto_id': 'num_productos', 'subtotal': 'monto_total'}, inplace=True)

    # Add rolling averages (if enough data)
    if len(df_agg) >= 7:
        df_agg = df_agg.sort_values('fecha')
        df_agg['rolling_avg_7d'] = df_agg.groupby('categoria_id')['monto_total'].transform(
            lambda x: x.rolling(window=7, min_periods=1).mean()
        )
        df_agg['rolling_avg_30d'] = df_agg.groupby('categoria_id')['monto_total'].transform(
            lambda x: x.rolling(window=30, min_periods=1).mean()
        )
    else:
        df_agg['rolling_avg_7d'] = df_agg['monto_total']
        df_agg['rolling_avg_30d'] = df_agg['monto_total']

    return df_agg


def train_model(df, test_size=0.2, random_state=42):
    """
    Train Random Forest Regressor model

    Args:
        df: DataFrame with prepared sales data
        test_size: Proportion of data to use for testing
        random_state: Random seed for reproducibility

    Returns:
        model: Trained RandomForestRegressor
        metrics: Dictionary with evaluation metrics
        features: List of feature names used
    """
    # Features for training
    feature_cols = ['año', 'mes', 'dia_semana', 'dia_mes', 'categoria_id',
                    'cantidad', 'num_productos', 'rolling_avg_7d', 'rolling_avg_30d']

    # Target variable
    target_col = 'monto_total'

    # Prepare features and target
    X = df[feature_cols].copy()
    y = df[target_col].copy()

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state
    )

    # Train Random Forest model
    model = RandomForestRegressor(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1  # Use all CPU cores
    )

    model.fit(X_train, y_train)

    # Make predictions on test set
    y_pred = model.predict(X_test)

    # Calculate metrics
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    r2 = r2_score(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)

    metrics = {
        'rmse': float(rmse),
        'r2_score': float(r2),
        'mae': float(mae),
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'features_used': feature_cols
    }

    return model, metrics, feature_cols


def save_model(model, metrics, features):
    """
    Save trained model and create ModelMetrics record

    Args:
        model: Trained model
        metrics: Dictionary with evaluation metrics
        features: List of feature names

    Returns:
        ModelMetrics object
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    model_filename = f'sales_predictor_{timestamp}.pkl'
    model_path = os.path.join(MODEL_DIR, model_filename)

    # Save model with joblib
    joblib.dump(model, model_path)

    # Deactivate previous models
    ModelMetrics.objects.filter(is_active=True).update(is_active=False)

    # Create new ModelMetrics record
    model_metrics = ModelMetrics.objects.create(
        model_name='RandomForestRegressor',
        rmse=metrics['rmse'],
        r2_score=metrics['r2_score'],
        mae=metrics['mae'],
        training_samples=metrics['training_samples'],
        features_used=features,
        model_path=model_path,
        is_active=True
    )

    return model_metrics


def load_model():
    """
    Load the active model from disk

    Returns:
        model: Loaded model
        model_metrics: ModelMetrics object
    """
    try:
        model_metrics = ModelMetrics.objects.filter(is_active=True).latest('trained_at')

        if not os.path.exists(model_metrics.model_path):
            raise FileNotFoundError(f"Model file not found: {model_metrics.model_path}")

        model = joblib.load(model_metrics.model_path)
        return model, model_metrics

    except ModelMetrics.DoesNotExist:
        raise ValueError("No active model found. Please train a model first.")


def predict_future_sales(days_ahead=30, by_category=True):
    """
    Generate sales predictions for future dates

    Args:
        days_ahead: Number of days to predict
        by_category: If True, predict by category; if False, predict total

    Returns:
        List of prediction dictionaries
    """
    model, model_metrics = load_model()

    # Get recent data for context (rolling averages)
    df = prepare_sales_data()

    # Get all categories
    categorias = Categoria.objects.all()

    predictions = []
    start_date = datetime.now().date()

    for day_offset in range(1, days_ahead + 1):
        pred_date = start_date + timedelta(days=day_offset)

        for categoria in categorias:
            # Get recent rolling averages for this category
            recent_data = df[df['categoria_id'] == categoria.id].tail(30)

            if len(recent_data) == 0:
                # No historical data for this category, skip or use defaults
                avg_7d = 0
                avg_30d = 0
                avg_cantidad = 0
                avg_num_productos = 0
            else:
                avg_7d = recent_data['rolling_avg_7d'].mean()
                avg_30d = recent_data['rolling_avg_30d'].mean()
                avg_cantidad = recent_data['cantidad'].mean()
                avg_num_productos = recent_data['num_productos'].mean()

            # Prepare features for prediction
            features = pd.DataFrame([{
                'año': pred_date.year,
                'mes': pred_date.month,
                'dia_semana': pred_date.weekday(),
                'dia_mes': pred_date.day,
                'categoria_id': categoria.id,
                'cantidad': avg_cantidad,
                'num_productos': avg_num_productos,
                'rolling_avg_7d': avg_7d,
                'rolling_avg_30d': avg_30d,
            }])

            # Make prediction
            predicted_amount = model.predict(features)[0]
            predicted_amount = max(0, predicted_amount)  # Ensure non-negative

            # Calculate confidence interval (simple estimation)
            std_dev = model_metrics.rmse if model_metrics.rmse else predicted_amount * 0.1
            confidence_lower = max(0, predicted_amount - 1.96 * std_dev)
            confidence_upper = predicted_amount + 1.96 * std_dev

            predictions.append({
                'prediction_date': pred_date,
                'categoria': categoria,
                'predicted_amount': round(predicted_amount, 2),
                'predicted_quantity': int(avg_cantidad),
                'confidence_interval_lower': round(confidence_lower, 2),
                'confidence_interval_upper': round(confidence_upper, 2),
            })

    return predictions


def save_predictions(predictions, model_metrics):
    """
    Save predictions to database

    Args:
        predictions: List of prediction dictionaries
        model_metrics: ModelMetrics object
    """
    # Delete old predictions for the same dates
    dates = [p['prediction_date'] for p in predictions]
    SalesPrediction.objects.filter(prediction_date__in=dates).delete()

    # Create new predictions
    prediction_objects = []
    for pred in predictions:
        prediction_objects.append(
            SalesPrediction(
                model_metrics=model_metrics,
                prediction_date=pred['prediction_date'],
                predicted_amount=pred['predicted_amount'],
                predicted_quantity=pred['predicted_quantity'],
                categoria=pred['categoria'],
                confidence_interval_lower=pred['confidence_interval_lower'],
                confidence_interval_upper=pred['confidence_interval_upper'],
            )
        )

    SalesPrediction.objects.bulk_create(prediction_objects)


def train_and_save_model():
    """
    Complete pipeline: prepare data, train, save model, generate predictions

    Returns:
        Dictionary with results
    """
    # Step 1: Prepare data
    df = prepare_sales_data()

    # Step 2: Train model
    model, metrics, features = train_model(df)

    # Step 3: Save model
    model_metrics = save_model(model, metrics, features)

    # Step 4: Generate predictions
    predictions = predict_future_sales(days_ahead=90)  # 3 months ahead

    # Step 5: Save predictions
    save_predictions(predictions, model_metrics)

    return {
        'success': True,
        'model_metrics': model_metrics,
        'metrics': metrics,
        'predictions_generated': len(predictions),
        'message': f'Model trained successfully with R² score: {metrics["r2_score"]:.3f}'
    }

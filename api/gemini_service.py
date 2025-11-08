import re
import json
from typing import Dict, List, Optional
from django.conf import settings
import google.generativeai as genai


class ProductoSimplificado:
    """Clase para representar productos simplificados para el chat"""
    def __init__(self, id: int, nombre: str, descripcion: str, precio: float, marca: str, categoria: str):
        self.id = id
        self.nombre = nombre
        self.descripcion = descripcion
        self.precio = precio
        self.marca = marca
        self.categoria = categoria

    def to_dict(self):
        return {
            'id': self.id,
            'nombre': self.nombre,
            'descripcion': self.descripcion,
            'precio': self.precio,
            'marca': self.marca,
            'categoria': self.categoria
        }


class GeminiService:
    """
    Service for handling Google Gemini AI chat interactions
    """

    def __init__(self):
        api_key = settings.GEMINI_API_KEY
        if not api_key:
            raise ValueError('GEMINI_API_KEY no está configurada en las variables de entorno')

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')

    def chat(self, user_message: str, productos: List[ProductoSimplificado]) -> Dict:
        """
        Process a chat message with Gemini AI

        Args:
            user_message: The user's message
            productos: List of available products

        Returns:
            Dict with 'response' (str) and 'productos' (List[Dict])
        """
        try:
            # Simplify products for context
            productos_dict = [p.to_dict() for p in productos]

            # Create context with product information
            contexto_productos = f"""Eres un asistente virtual de una farmacia. Tienes acceso al siguiente catálogo de productos:

{json.dumps(productos_dict, indent=2, ensure_ascii=False)}

Tu trabajo es:
1. Ayudar a los usuarios a encontrar medicamentos y productos de salud según sus síntomas o necesidades
2. Recomendar productos específicos de nuestro catálogo que puedan ayudarles
3. Ser amable, profesional y empático
4. Si recomendas productos, menciona su nombre exacto, marca y precio
5. Recuerda que NO puedes diagnosticar, solo recomendar productos de venta libre
6. Si el síntoma es grave, sugiere consultar con un médico

Importante: Al recomendar productos, DEBES incluir el ID del producto en tu respuesta en el siguiente formato:
[PRODUCTO:id:nombre]

Por ejemplo: "Te recomiendo [PRODUCTO:5:Paracetamol 500mg] para aliviar tu dolor de cabeza."

Usuario: {user_message}"""

            # Generate response
            response = self.model.generate_content(contexto_productos)
            text = response.text

            # Extract recommended products
            productos_recomendados = self._extraer_productos_recomendados(text, productos)

            return {
                'response': text,
                'productos': [p.to_dict() for p in productos_recomendados]
            }

        except Exception as e:
            print(f'Error en chat AI: {str(e)}')
            raise Exception('Error al procesar el mensaje')

    def _extraer_productos_recomendados(self, texto: str, productos: List[ProductoSimplificado]) -> List[ProductoSimplificado]:
        """
        Extract recommended products from the AI response

        Args:
            texto: The AI response text
            productos: List of all available products

        Returns:
            List of recommended products
        """
        productos_recomendados = []

        # Search for pattern [PRODUCTO:id:nombre]
        pattern = r'\[PRODUCTO:(\d+):([^\]]+)\]'
        matches = re.finditer(pattern, texto)

        for match in matches:
            producto_id = int(match.group(1))
            producto = next((p for p in productos if p.id == producto_id), None)

            if producto and producto not in productos_recomendados:
                productos_recomendados.append(producto)

        return productos_recomendados

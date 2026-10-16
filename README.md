# Gatekeeper Proxy

Gatekeeper Proxy es un prototipo en TypeScript/Node.js de un proxy HTTP configurable. El código incluye reglas de firewall, limitación de solicitudes y una pequeña interfaz de administración.

## Requisitos

- Node.js 22+
- npm

## Ejecutar localmente

```bash
git clone https://github.com/tatitoxt/gatekeeper-proxy.git
cd gatekeeper-proxy
npm install
npm run dev
```

Para compilar y ejecutar la versión compilada:

```bash
npm run build
npm start
```

El comando `npm test` está configurado en el proyecto. Revisá la cobertura actual antes de tomarla como garantía del comportamiento.

La configuración de ejemplo está en [gatekeeper.config.json](gatekeeper.config.json). Cambiá los valores para tu entorno y mantené el panel administrativo en una red local o protegida. Este proyecto no fue auditado como WAF ni debe considerarse una capa de seguridad lista para producción.

## Licencia

MIT. Ver [LICENSE](LICENSE).

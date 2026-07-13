# Bre-Pay — Pagos digitales Bre-B con RSA (firma + cifrado)

Prototipo académico (MVP) de un sistema de pagos inspirado en llaves **Bre-B**, usando criptografía de clave pública **RSA** para:

| Propiedad | Mecanismo |
|-----------|-----------|
| Autenticidad | Firma RSA-PSS + SHA-256 |
| Integridad | La firma falla si el payload se altera |
| No repudio | Solo el dueño de la privada puede firmar |
| Confidencialidad | Cifrado híbrido RSA-OAEP + AES-256-GCM |

## Requisitos

- Python 3.10+
- Dependencias en `requirements.txt`

```bash
cd breb_pay
pip install -r requirements.txt
python app.py
```

Abre http://127.0.0.1:5000

## Cuentas demo prestablecidas

Contraseña para todas: `demobreb`

| Usuario | Nombre | Llave Bre-B | Tipo |
|---------|--------|-------------|------|
| `ana` | Ana Pérez | `3001002001` | teléfono |
| `carlos` | Carlos Ruiz | `carlos@brepay.co` | email |
| `maria` | María Gómez | `1002003001` | documento |
| `andres` | Andrés López | `andres.pay` | alfanumérica |

En la landing, el menú inferior muestra estas cuentas. En login puedes abrir una con un clic.

## Arquitectura

- `app.py` — rutas Flask (usuarios, Bre-B, transferencias, verificación)
- `crypto_service.py` — generación de claves, firma, verificación, cifrado/descifrado
- `db.py` — SQLite (`instance/breb_pay.db`)
- `templates/` + `static/` — interfaz web

## Alcance (MVP)

Incluye registro/login, claves RSA, llaves Bre-B, saldo virtual, transferencias firmadas y cifradas, historial y demo de integridad.

No incluye bancos reales, pasarelas ni validación gubernamental.

## Equipo / propuesta

Alineado a la *Propuesta de Visibilidad Tecnológica*: sistema seguro de pagos digitales basado en llaves Bre-B y criptografía RSA, extendido con **cifrado del payload** (Propuesta B).

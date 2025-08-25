# Solid OIDC Vanilla JS sandbox

A sandbox to break down the Solid OIDC authentication flow implemented in vanilla JavaScript (without SOLID libraries). This project breaks down the sequence of steps involved in authenticating a user using Solid OIDC protocol.

## Prerequisites

- Docker and Docker Compose installed on your system
- Node.js and npm (for local development)

## Project Structure

The project consists of:
- Static HTML/CSS/JavaScript files in the `dist` directory
- A sequence diagram showing the Solid OIDC authentication flow
- Docker configuration for serving the application

## Running the Application

### Using Docker Compose

1. Clone this repository:
```bash
git clone <repository-url>
cd solid-oidc-vanilla-js
```

2. Make sure you have the static files in the `dist` directory

3. Start the application using Docker Compose:
```bash
docker compose up -d
```

4. Access the application in your browser at:
```
http://localhost:1234
```

5. To stop the application:
```bash
docker compose down
```

## Development

For local development without Docker, you can serve the `dist` directory using any static file server.

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# Attack Surface Monitoring SaaS

A Flask-based SaaS application for monitoring and managing attack surfaces with a comprehensive dashboard interface.

## Features

- **User Authentication**: Secure login and registration system
- **Multi-tenant Architecture**: Each user has their own organization and data
- **Asset Management**: Track domains, subdomains, IP addresses, and cloud resources
- **Vulnerability Monitoring**: Monitor and track security vulnerabilities
- **Alert System**: Real-time alerts for security issues
- **Interactive Dashboard**: Beautiful dashboard with charts and metrics
- **RESTful API**: Complete API for programmatic access

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite (easily configurable for PostgreSQL)
- **Frontend**: HTML5, TailwindCSS, ECharts for visualizations
- **Authentication**: Flask-Login with bcrypt password hashing
- **Forms**: Flask-WTF with CSRF protection

## Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd attacksurface
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   - Copy `.env` file and update the values as needed
   - The default configuration uses SQLite and works out of the box

5. **Run the application**
   ```bash
   python run.py
   ```

6. **Access the application**
   - Open your browser and go to `http://localhost:5000`
   - Use the default credentials: `admin` / `password`

## Project Structure

```
attacksurface/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── models.py             # Database models
├── forms.py              # WTForms definitions
├── run.py                # Application runner
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables
├── templates/            # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   └── auth/
│       ├── login.html
│       └── register.html
├── routes/               # Route blueprints
│   ├── __init__.py
│   ├── auth.py          # Authentication routes
│   └── api.py           # API endpoints
└── static/              # Static files (CSS, JS, images)
```

## API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/logout` - User logout

### Assets
- `GET /api/assets` - Get all assets
- `POST /api/assets` - Create new asset

### Vulnerabilities
- `GET /api/vulnerabilities` - Get all vulnerabilities

### Alerts
- `GET /api/alerts` - Get all alerts

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

## Database Models

- **User**: User accounts with authentication
- **Organization**: Multi-tenant organization structure
- **Asset**: Tracked assets (domains, IPs, etc.)
- **Vulnerability**: Security vulnerabilities
- **Alert**: Security alerts and notifications
- **ScanResult**: Security scan results

## Configuration

The application supports multiple environments:

- **Development**: SQLite database, debug mode enabled
- **Production**: PostgreSQL recommended, debug disabled
- **Testing**: In-memory SQLite, CSRF disabled

Configure via environment variables in `.env` file.

## Security Features

- CSRF protection on all forms
- Password hashing with bcrypt
- Session management with Flask-Login
- SQL injection protection via SQLAlchemy ORM
- Input validation with WTForms

## Deployment

### Production Deployment

1. **Set environment variables**
   ```bash
   export FLASK_CONFIG=production
   export SECRET_KEY=your-production-secret-key
   export DATABASE_URL=postgresql://user:pass@localhost/dbname
   ```

2. **Use a production WSGI server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8000 "app:create_app()"
   ```

3. **Set up a reverse proxy** (nginx recommended)

### Docker Deployment

Create a `Dockerfile`:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "run.py"]
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions, please open an issue in the repository.

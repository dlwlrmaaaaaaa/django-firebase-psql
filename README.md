# CRISPY PATA Backend

## Overview

CRISPY PATA is a Django backend application that features a custom authentication system allowing users to log in using either their username or email. The backend utilizes Django REST Framework (DRF) and PostgreSQL for user management.

## Features

- Custom User Authentication: Users can log in using either their username or email.
- Role-based Management: Different user roles with customized permissions.
- Secure Registration & Login: Password validation and token-based authentication using JWT (JSON Web Tokens).

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL
- Django
- Firebase account for real-time data management

### Backend Setup

1. Clone the repository:
```bash
   git clone https://github.com/yourusername/crispy-pata.git
   cd crispy-pata
```
2. Set up a virtual environment:
```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```
3. Install dependencies:
```bash
   pip install -r requirements.txt
```
4. Set up your PostgreSQL database and apply migrations:
```bash
   python manage.py migrate
```

5. Run the development server:
```bash
   python manage.py runserver 0.0.0.0:8000
```
## Configuration

### Database

The project uses PostgreSQL for data storage. In the settings.py file, configure your database settings:

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your_db_name',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

### Firebase Setup
### This firebase setup ask the owner for it 

## Testing

To run the tests:
```
python manage.py test
```
## License

This project is licensed under the MIT License.

## Contact

For any inquiries, please contact your-email@example.com.

# Microservices Tutorial

A hands-on learning project for backend microservices development using Python and FastAPI.

## 📚 Overview

This project is a practical exploration of microservices architecture, currently focusing on building an authentication service from scratch. The goal is to learn core backend concepts including API development, database management, security, and service-oriented architecture.

## 🏗️ Project Structure

```
MICROSERVICE_TUTORIAL/
├── auth/                    # Authentication microservice
│   ├── config.py           # Configuration settings
│   ├── database.py         # Database connection and models
│   ├── routes.py           # API endpoints
│   ├── tokens.py           # JWT token management
│   ├── verification.py     # User verification logic
│   └── tests/              # Test suite
│       ├── auth_test.py
│       └── db_test.py
├── main.py                 # Main application entry point
├── requirements.txt        # Project dependencies
└── README.md              # This file
```

## 🚀 Current Features

### Authentication Service
- ✅ User registration with email validation
- ✅ Password hashing using bcrypt
- ✅ JWT token generation
- ✅ Database integration with SQLAlchemy
- ✅ Email verification system
- ✅ Input validation using Pydantic

## 🛠️ Tech Stack

- **Framework**: FastAPI
- **Database**: MySQL with SQLAlchemy ORM
- **Authentication**: JWT (python-jose), bcrypt
- **Validation**: Pydantic
- **Environment Management**: python-dotenv

## 📋 Prerequisites

- Python 3.8+
- MySQL database
- pip package manager

## ⚙️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd MICROSERVICE_TUTORIAL
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file in the root directory with:
```
DATABASE_URL=mysql+mysqlconnector://username:password@localhost/dbname
SECRET_KEY=your-secret-key
```

4. Run the application:
```bash
uvicorn auth.routes:app --reload
```

## 🎯 API Endpoints

### Authentication Service

#### Register New User
```http
POST /register
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@example.com",
  "password": "securepassword123"
}
```

**Response**: `201 Created`
```json
{
  "message": "User registered successfully",
  "user_id": "uuid"
}
```

## 🧪 Testing

Run tests using:
```bash
pytest auth/tests/
```

## 📖 Learning Goals

- [x] Set up FastAPI application
- [x] Implement user registration
- [x] Database integration with SQLAlchemy
- [x] Password hashing and security
- [x] JWT token implementation
- [ ] User login endpoint
- [ ] Token refresh mechanism
- [ ] Role-based access control (RBAC)
- [ ] Additional microservices (e.g., user profile, products)
- [ ] Inter-service communication
- [ ] Docker containerization
- [ ] API Gateway implementation

## 🔐 Security Features

- Password hashing with bcrypt
- JWT token-based authentication
- Email validation
- Input sanitization with Pydantic
- Secure password requirements (minimum 6 characters)

## 🤝 Contributing

This is a personal learning project, but suggestions and feedback are welcome!

## 📝 Notes

This project is actively being developed as part of my journey to learn backend microservices architecture. Features and structure will evolve as I progress through different concepts and best practices.

## 📄 License

This project is for educational purposes.

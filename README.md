# BSN Knowledge API

![Python](https://img.shields.io/badge/python-3.12+-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Status](https://img.shields.io/badge/status-production-brightgreen.svg) ![HIPAA](https://img.shields.io/badge/HIPAA-compliant-blue.svg) ![Tests](https://img.shields.io/badge/tests-485%2B-brightgreen.svg) ![Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen.svg)

Comprehensive nursing education platform with AI-powered content generation, competency assessment, and learning analytics.

## 🎓 Overview

**BSN Knowledge** is a complete educational API designed specifically for nursing education, providing advanced learning tools aligned with the AACN Essentials framework. The platform empowers nursing students, instructors, and administrators with intelligent, evidence-based educational resources.

**Platform Highlights:**
- 🤖 **AI-Powered Content Generation** - Unlimited NCLEX questions and study materials
- 📊 **AACN Competency Framework** - Complete assessment and tracking system
- 📈 **Learning Analytics** - Detailed progress tracking and predictive modeling
- 🏥 **Clinical Decision Support** - Evidence-based learning scenarios
- 🔒 **Enterprise Security** - JWT authentication, RBAC, and HIPAA compliance
- ⚡ **Production Ready** - 485+ tests, >90% coverage, <500ms response times

## 🚀 Quick Start

### Get API Access
```bash
# Authenticate and get your JWT tokens
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

### Generate NCLEX Questions
```bash
# Create AI-powered nursing practice questions
curl -X POST https://api.bsn-knowledge.edu/api/v1/nclex/generate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "Cardiovascular Nursing",
    "difficulty": "intermediate",
    "question_count": 5,
    "settings": {
      "include_rationales": true,
      "medical_accuracy_check": true
    }
  }'
```

### Assess Student Competency
```bash
# Evaluate nursing competencies using AACN framework
curl -X POST https://api.bsn-knowledge.edu/api/v1/assessment/competency \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "student_id": "student_12345",
    "competency_id": "aacn_domain_2_comp_1",
    "performance_data": {
      "quiz_scores": [88, 91, 85],
      "clinical_evaluation": {
        "patient_care": 4.2,
        "critical_thinking": 3.9
      }
    }
  }'
```

## 📚 Comprehensive Documentation

### 🔗 [Complete Documentation Portal →](docs/)

Our documentation is organized into comprehensive sections:

#### 📖 **API Reference**
- **[Overview & Getting Started](docs/api-reference/overview.md)** - Core concepts and quick start
- **[Authentication Guide](docs/api-reference/authentication.md)** - JWT authentication and security
- **[NCLEX Generation](docs/api-reference/endpoints/nclex.md)** - AI-powered question generation
- **[Assessment & Competency](docs/api-reference/endpoints/assessment.md)** - AACN framework evaluation
- **[Analytics & Reporting](docs/api-reference/endpoints/analytics.md)** - Learning analytics and insights
- **[Study Guide Creation](docs/api-reference/endpoints/study-guides.md)** - Personalized study materials
- **[Error Handling](docs/api-reference/error-handling.md)** - Error codes and troubleshooting

#### 👨‍💻 **Developer Resources**
- **[Getting Started Guide](docs/developer-guide/getting-started.md)** - Complete setup walkthrough
- **[SDK Examples](docs/developer-guide/sdk-examples.md)** - Python, JavaScript, and more
- **[Integration Patterns](docs/developer-guide/integration-guide.md)** - Common implementation patterns
- **[Best Practices](docs/developer-guide/best-practices.md)** - Performance and security guidelines

#### 👩‍🎓 **User Guides**
- **[Student Guide](docs/user-guides/student-guide.md)** - Learning features and workflows
- **[Instructor Guide](docs/user-guides/instructor-guide.md)** - Course management tools
- **[Administrator Guide](docs/user-guides/admin-guide.md)** - System administration

#### 🏗️ **Technical Documentation**
- **[System Architecture](docs/technical/architecture.md)** - Comprehensive architecture overview
- **[Database Schema](docs/technical/database-schema.md)** - Data models and relationships
- **[Security Architecture](docs/technical/security.md)** - Security implementation details
- **[Performance Guide](docs/technical/performance.md)** - Scaling and optimization
- **[Deployment Guide](docs/technical/deployment.md)** - Production deployment

#### 🔒 **Compliance & Security**
- **[HIPAA Compliance](docs/compliance/hipaa-compliance.md)** - Educational data protection
- **[Security Best Practices](docs/compliance/security-best-practices.md)** - Implementation guidelines
- **[Data Privacy](docs/compliance/data-privacy.md)** - Student data protection

### 🌐 **Interactive Resources**
- **[Swagger UI](https://api.bsn-knowledge.edu/docs)** - Interactive API documentation
- **[ReDoc](https://api.bsn-knowledge.edu/redoc)** - Alternative API documentation
- **[OpenAPI Specification](https://api.bsn-knowledge.edu/openapi.json)** - Machine-readable API spec

## 🎯 Key Features

### 🔐 **Enterprise Authentication & Security**
- JWT-based authentication with 30-minute access tokens
- Role-based access control (Student, Instructor, Admin)
- Rate limiting with tiered endpoint restrictions (1,000-50 requests/hour)
- Comprehensive audit logging and monitoring
- HIPAA-compliant data handling and encryption

### 🧠 **AI-Powered NCLEX Generation**
- Unlimited practice questions using RAGnostic AI integration
- Evidence-based rationales with clinical references
- Customizable difficulty levels and nursing specialties
- Medical accuracy validation against current standards
- Support for multiple question types (multiple choice, SATA, etc.)

### 📊 **AACN Competency Assessment**
- Complete implementation of AACN Essentials framework
- Eight domain competency tracking and evaluation
- Five-level proficiency assessment (Novice to Expert)
- Detailed gap analysis and learning recommendations
- Competency progression tracking and graduation readiness

### 📈 **Advanced Learning Analytics**
- Real-time progress tracking and performance monitoring
- Predictive modeling for NCLEX readiness and academic success
- Personalized learning path recommendations
- Institutional effectiveness reporting and benchmarking
- Comprehensive engagement metrics and intervention alerts

### 🎯 **Adaptive Learning Engine**
- Personalized study guide generation based on competency gaps
- Intelligent content recommendations using ML algorithms
- Learning pattern analysis and optimization suggestions
- Spaced repetition and knowledge retention strategies

## 📊 Technical Specifications

### **Performance Metrics**
- **Response Times**: <500ms for standard operations, <2s for AI generation
- **Concurrent Users**: 1,000+ simultaneous users supported
- **Availability**: 99.9% uptime SLA with monitoring and alerting
- **Test Coverage**: 485+ comprehensive tests with >90% code coverage
- **Rate Limiting**: Intelligent throttling across 4 endpoint tiers

### **Technology Stack**
- **Backend**: Python 3.12+ with FastAPI and async/await patterns
- **Authentication**: JWT tokens with RBAC and session management
- **Database**: Multi-database support (PostgreSQL, Redis, SQLite)
- **AI Integration**: RAGnostic AI service with circuit breaker patterns
- **Caching**: Redis-based caching with configurable TTL policies
- **Monitoring**: Comprehensive logging, metrics, and health checks

### **Architecture Highlights**
- **Microservices Design**: Modular, scalable service architecture
- **Event-Driven Processing**: Asynchronous analytics and notifications
- **Circuit Breaker Patterns**: Resilient external service integration
- **Container-Ready**: Docker support with Kubernetes orchestration
- **API-First Design**: Complete OpenAPI 3.0 specification

## 🛠️ Installation & Development

### **Prerequisites**
- Python 3.12+ (standardized workspace requirement)
- UV package manager (canonical virtual environment)
- Redis server (for caching and sessions)
- PostgreSQL (production database)
- Docker and Docker Compose (optional)

### **Quick Setup**
```bash
# Clone repository
git clone https://github.com/bsn-knowledge/api.git
cd bsn_knowledge

# Install dependencies with UV
uv sync --all-extras

# Run tests
make test

# Start development server
make dev

# Visit API documentation
open http://localhost:8000/docs
```

### **Production Deployment**
```bash
# Build production image
docker build -t bsn-knowledge/api .

# Start with Docker Compose
docker-compose up -d

# Run health checks
make health-check
```

## 📈 API Statistics & Usage

### **Current Metrics**
- **Total Endpoints**: 40+ RESTful API endpoints
- **Authentication Methods**: 8 auth-related endpoints with OAuth2 compatibility
- **Content Generation**: 15+ AI-powered generation endpoints
- **Analytics**: 12 comprehensive analytics and reporting endpoints
- **Assessment**: 10+ competency evaluation and tracking endpoints

### **Rate Limits by Category**
| Endpoint Category | Requests/Hour | Purpose |
|-------------------|---------------|----------|
| **General API** | 1,000 | Standard operations and data access |
| **Content Generation** | 50 | AI-powered question and content creation |
| **Assessment** | 200 | Competency evaluations and analysis |
| **Analytics** | 500 | Progress tracking and reporting |

### **Response Time Targets**
- **Authentication**: <100ms average response time
- **Data Retrieval**: <300ms for student progress and competency data
- **Analytics Generation**: <1s for complex reports and insights
- **AI Content Generation**: <2s for NCLEX questions with rationales

## 🤝 Community & Support

### **Getting Help**
- **📧 Technical Support**: support@bsn-knowledge.edu
- **📖 Documentation**: [docs.bsn-knowledge.edu](https://docs.bsn-knowledge.edu)
- **🔍 Status Page**: [status.bsn-knowledge.edu](https://status.bsn-knowledge.edu)
- **💬 Community Forum**: [community.bsn-knowledge.edu](https://community.bsn-knowledge.edu)

### **Contributing**
- **🐛 Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **💡 Feature Requests**: Propose enhancements via GitHub Discussions
- **🔧 Pull Requests**: Follow our [Contributing Guide](CONTRIBUTING.md)
- **📝 Documentation**: Help improve our comprehensive documentation

### **Educational Partnership**
- **🏫 Institution Integration**: Custom deployment and training available
- **🎓 Faculty Support**: Dedicated support for nursing educators
- **📊 Research Collaboration**: Partner with us on nursing education research
- **🌟 Beta Program**: Early access to new features and capabilities

## 📄 License & Legal

**Open Source License**: This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**HIPAA Compliance**: Educational data handling meets HIPAA requirements when applicable. See our [HIPAA Compliance Guide](docs/compliance/hipaa-compliance.md) for details.

**Educational Use**: Designed specifically for nursing education and not intended for clinical decision-making or patient care.

---

**BSN Knowledge API** - Empowering the next generation of nursing professionals through innovative technology and evidence-based education.

*Version 1.0.0 | Last Updated: 2024-08-24 | [View Changelog](CHANGELOG.md)*

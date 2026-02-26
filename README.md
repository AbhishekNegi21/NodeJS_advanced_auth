# Advanced Auth API
## Node.js + TypeScript

A production-style authentication system built with Node.js, Express, TypeScript, and MongoDB, implementing secure JWT authentication with refresh token rotation and modern security practices.

Built as a portfolio project to demonstrate backend authentication architecture and security best practices.

# Features

- User Registration & Login

- Password hashing with bcrypt

- JWT Access Tokens (30 min expiry)

- Refresh Tokens stored in HttpOnly cookies

- Refresh Tokens stored in MongoDB (DB-backed sessions)

- Refresh Token Rotation

- Logout (single device)

- Logout from all devices

- Protected Routes Middleware

- Input validation using Zod

- Environment-based configuration

- Fully type-safe architecture (TypeScript).

# Tech Stack

- Node.js / Express.js

- TypeScript

- MongoDB / Mongoose

- bcrypt

- jsonwebtoken / crypto

- Zod

# Project Structure

```
.
├── scripts/
├── src/
│   ├── config/
│   ├── controllers/
│   │   └── auth/
│   ├── lib/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── types/
│   ├── app.ts
│   └── server.ts
├── .env
├── package.json
└── tsconfig.json
```

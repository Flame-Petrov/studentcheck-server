# App Resume

**StudentCheck** is a web-based student attendance and class management platform built for two roles: students and teachers. Students can log in, view their assigned classes, see attendance totals, and display a personal QR code used for attendance check-in. Teachers can log in to a dashboard where they create classes, add or remove students, track attendance sessions, review attendance history, and manage class rosters through overlay-based workflows.

The app includes several supporting systems around that core flow. There is a billing area for subscription and plan management, an AI-powered support chat for in-app help, and utilities for exporting or backing up operational data. The backend exposes APIs for authentication, registration, student/class management, attendance tracking, summaries, and administrative maintenance tasks.

From a technical perspective, the frontend is a multi-page web app using HTML, CSS, and modular JavaScript. The backend is a Node.js/Express service with a PostgreSQL database. It includes custom token-based authentication, input validation, rate limiting on sensitive routes, encrypted handling of certain user fields, backup/import tooling, and automated tests around authentication, registration, serialization, and attendance-related logic.

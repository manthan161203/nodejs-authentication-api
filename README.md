# Authentication API

This project is an authentication API built using Node.js, Express.js, MongoDB, and JWT for user authentication and management.

## Setup

1. Clone the repository:

    ```
    git clone <repository-url>
    ```

2. Install dependencies:

    ```
    npm install
    ```

3. Set up environment variables:

    Create a `.env` file in the root directory of the project and add the following environment variables:

    ```
    MONGODB_URI=<Your MongoDB connection URI>
    PORT=<Port number for the server>
    JWT_EXPIRES_IN=<JWT expiration time>
    MAIL_FOR_OTP=<Email address for sending OTP>
    PASS_FOR_OTP=<Password for email account>
    ```

## Environment Variables

- `MONGODB_URI`: MongoDB connection URI for connecting to the database.
- `PORT`: Port number for running the server.
- `JWT_EXPIRES_IN`: Expiration time for JWT tokens (e.g., `"1h"` for 1 hour).
- `MAIL_FOR_OTP`: Email address used for sending OTP (One-Time Password).
- `PASS_FOR_OTP`: Password for the email account used for sending OTP.

## Usage

To start the server, run the following command:

    ```
    npm start
    ```


The server will start running on the specified port.

## Endpoints

- **POST /api/auth/register**: Register a new user.
  - Request Body:
    - `username`: Username of the user (required).
    - `email`: Email address of the user (required).
    - `password`: Password for the user (required, min 6 characters).
    - `phoneNumber`: Phone number of the user (required).
    - `firstName`: First name of the user (required).
    - `lastName`: Last name of the user (required).

- **POST /api/auth/login**: Login with email/username and password.
  - Request Body:
    - `emailOrUsername`: Email address or username (required).
    - `password`: Password (required).

- **POST /api/auth/change-password**: Change user's password (requires authentication).
  - Request Body:
    - `emailOrUsername`: Email address or username (required).
    - `oldPassword`: Old password (required).
    - `newPassword`: New password (required, min 6 characters).

- **POST /api/auth/forget-password**: Request to reset password via email OTP.
  - Request Body:
    - `email`: Email address for password reset (required).

- **POST /api/auth/reset-password**: Reset user's password using OTP received via email.
  - Request Body:
    - `email`: Email address (required).
    - `OTP`: One-Time Password received via email (required).
    - `newPassword`: New password (required, min 6 characters).

- **POST /api/auth/profile**: View user's profile information (requires authentication).
  - Request Body:
    - `emailOrUsername`: Email address or username (required).

- **POST /api/auth/users**: View list of users (requires authentication).

## License

This project is licensed under the [MIT License](LICENSE).

import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header
    if (!token) {
        return res.status(401).json({ message: 'Access token is missing or invalid' });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user; // Attach the user data to the request object
        return next(); // Proceed to the next middleware or route handler
    });
    return; // Ensure all code paths return a value
};

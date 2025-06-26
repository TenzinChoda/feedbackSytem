const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

// Middleware to check if user is authenticated
const authenticateUser = (req, res, next) => {
    if (!req.cookies.token) {
        return res.redirect('/login');
    }
    next();
};

// User dashboard route
router.get('/dashboard', authenticateUser, (req, res) => {
    res.render('user/dashboard');
});

// User food viewing route
router.get('/food', authenticateUser, (req, res) => {
    res.render('user/food');
});

router.get('/foods', userController.getAllFoods);

module.exports = router;
//jshint esversion:6
require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const ejs = require('ejs');
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: "This is secret Key",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/secretsDB', {useNewUrlParser: true,  useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);
const userSchema = new mongoose.Schema ({
  userEmail: String,
  userPassword: String,
  googleId: String,
  userSecret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema);
passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());//create cookie
// passport.deserializeUser(User.deserializeUser());//destroy cookie
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo' //deal with google+ deprication
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});

app.get("/login", function(req, res){
  res.render('login');
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets",function(req, res){
  User.find({"userSecret": {$ne: null}}, function(err, foundUser){
    if(err)
    console.log(err);
    else{
      if(foundUser)
      {
        res.render("secrets", {userWithSecrets: foundUser});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");//if cookie stored
  } else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user._id, function(err, foundUser){
    if(err) console.log(err);
    else{
      if(foundUser){
        foundUser.userSecret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){
  //create a hash & salted passwod automatically & register the new user
  User.register({username: req.body.username},req.body.password, function(err, user){
    if(err)
    {
      console.log(err);
      res.redirect("/register");
    }
    else
    {
      passport.authenticate("local")(req, res , function(){
        res.redirect("/secrets");
      });
    }
  });//user.register end
});

app.post("/login", function(req, res){
  const user = new User({
    userEmail: req.body.username,
    userPassword: req.body.password
  });
  //need to check here
  req.login(user, function(err){
    if(err)
      console.log(err);
    else{
        passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});





app.listen(3000, function(){
  console.log("server started at port 3000");
});

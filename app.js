//jshint esversion:6
//RESTARTING SERVER DESTROYS ALL COOKIES AND SESSIONS
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
var findOrCreate = require('mongoose-findorcreate');

const app = express();
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,     //secret should be in your .env file
    resave: false,
    saveUninitialized: false
}));
//The above code setting i.e resave and saveUninitialized are recommended by the package documentation itself
app.use(passport.initialize());   //sets up to start using
app.use(passport.session());	    //sets up the passport to manage our sessions

mongoose.connect("mongodb://localhost:27017/UserDB",{useNewUrlParser:true});
//mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    secret : String
});
userSchema.plugin(passportLocalMongoose);   //This will basically do major amount of stuff like hashing and salting
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACKURL,
    userProfileURL: process.env.USERPROFILEURL
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.post("/register",function(req,res){
    User.register({username: req.body.username,active:false},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
app.post("/login",function(req,res){
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/",function(req,res){
    res.render('home');
});
app.get("/auth/google",passport.authenticate("google", { scope: ["profile"] }));

app.get('/auth/google/secrets', 

passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

app.get("/login",function(req,res){
    res.render('login');
});
app.get("/register",function(req,res){
    res.render('register');
});
app.get("/secrets",function(req,res){
    User.find({"secret": {$ne:null}},function(err,foundUsers){
        if(err){
            console.log(err);
        }
        res.render("secrets",{userWithSecrets:foundUsers});
    });
});
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/login");
    }
})
app.get("/logout", function(req, res){
    req.logout(function(){
        res.redirect("/");
    });
    
});

app.listen(3000,function(){
    console.log("Server started at 3000");
});
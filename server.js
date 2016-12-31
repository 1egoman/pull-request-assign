const express = require('express'), app = express();
const passport = require('passport');
const uuid = require('uuid');
const request = require('request');
const _ = require('lodash');

// ------------------------------------------------------------------------------
// Database initialization
// ------------------------------------------------------------------------------
const Datastore = require('nedb'), db = {};
db.users = new Datastore({filename: './users.db', autoload: true});
db.repos = new Datastore({filename: './repos.db', autoload: true});

/*
 * User:
 * {
 *   "name": "1egoman",
 *   "token": "foobarbaz",
 *   "email": "me@me.me",
 *   ""
 * }
 *
 * Repo:
 * {
 *   "owner": "1egoman",
 *   "name": "aok",
 *   "admins": ["1egoman", "foo", "bar"],
 *   "assignees": ["1egoman", "foo", "bar", "baz"]
 * }
 */

function validateUser(user) {
  return user.name && user.token && user.email;
}
function validateRepo(user) {
  return user.owner && user.name && user.admins;
}

// ----------------------------------------------------------------------------
// Passport middleware and requirements
// ----------------------------------------------------------------------------
app.use(require('serve-static')(__dirname + '/../../public'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

// ----------------------------------------------------------------------------
// Strategy
// ----------------------------------------------------------------------------
const GitHubStrategy = require('passport-github').Strategy;
passport.use(new GitHubStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.REDIRECT_URI,
}, function(accessToken, refreshToken, profile, cb) {
  return db.users.findOne({name: profile.username}, (err, user) => {
    if (err) {
      return cb(err);
    } else if (!user) {
      // Insert a new user when the user isn't already in the database.
      return db.users.insert({
        name: profile.username,
        token: accessToken,
        avatar: profile.photos.find(i => i.value).value,
        secret: uuid.v4(),
      }, cb);
    } else {
      // User already exists.
      let changes = {token: accessToken};
      return db.users.update({name: profile.username}, changes, err => {
        cb(err, Object.assign({}, user, changes));
      });
    }
  });
}));

// ------------------------------------------------------------------------------
// Serialize and deserialize
// ------------------------------------------------------------------------------
passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(_id, done) {
  db.users.findOne({_id}, done);
});

// ------------------------------------------------------------------------------
// Authentication Routes
// ------------------------------------------------------------------------------

// Authenticate a user
app.get('/login', passport.authenticate('github', {
  successRedirect: '/',
  failureRedirect: '/login',
  scope: ["repo", "write:repo_hook", "user:email"],
}));

// Second leg of the auth
app.get("/callback", passport.authenticate("github", {
  failureRedirect: '/login',
}), (req, res) => {
  res.status(201).send({
    status: 'ok',
    msg: 'Successfully authenticated yourself.',
    secret: req.user.secret,
  });
});

// ------------------------------------------------------------------------------
// Setting up or tearing down a repository
// ------------------------------------------------------------------------------

function findOrCreateRepo(owner, name, user, opts, cb) {
  db.repos.findOne({name, owner}, (err, data) => {
    if (err) {
      cb(err);
    } else if (!data) {
      // Create a repository if it doesn't exist.
      db.repos.insert({
        name,
        owner,
        admins: [user.name],
        assignees: opts && opts.assignees ? opts.assignees : [user.name],
        secret: uuid.v4(), // a secret used for referrring to the repo in requests
      }, cb);
    } else {
      cb(null, data);
    }
  });
}

function createWebhook(repo, cb) {
  // TODO
  cb(null);
}

function teardownWebhook(repo, cb) {
  // TODO
  cb(null);
}

// Add a repo to the list of repos
app.get('/v1/repos/:owner/:name/setup', (req, res) =>{
  if (req.user) {
    // first, create the repo
    findOrCreateRepo(req.params.owner, req.params.name, req.user, {
      // allow custom assignees to be passed in
      assignees: req.query.assignees ? req.query.assignees.split(',') : null,
    }, (err, repo) => {
      if (err) {
        res.status(500);
      } else {
        // then, set up the webhooks
        createWebhook(repo, err => {
          if (err) {
            res.status(500);
          } else {
            res.send({
              status: 'ok',
              msg: `Added webhook to repo ${req.params.owner}/${repo.name}`,
              user_secret: req.user.secret,
              repo_secret: repo.secret,
              webhook: `/v1/assign?user=${req.user.secret}&repo=${repo.secret}`,
            });
          }
        });
      }
    });
  } else {
    // Not logged in, redirect.
    return res.redirect('/login');
  }
});

// Tear down a repository and repove it from the databse
app.get('/v1/repos/:owner/:name/teardown', (req, res) =>{
  if (req.user) {
    // first, create the repo
    db.repos.remove({
      owner: req.params.owner,
      name: req.params.name,
      admins: req.user.name, // make sure the currently logged in user can delete this repo.
    }, (err, repo) => {
      if (err) {
        res.status(500);
      } else if (repo === 0) {
        // Query didn't match anything.
        res.send({
          status: 'ok',
          msg: `You don't have permission to teardown that repository, or it hasn't been set up.`,
        });
      } else {
        // Permission has been sorted. Next, teardown the webhook.
        teardownWebhook(repo, err => {
          if (err) {
            res.status(500);
          } else {
            // And respond with a success!
            res.send({
              status: 'ok',
              msg: `Tore down repository ${req.params.owner}/${req.params.name}`,
            });
          }
        });
      }
    });
  } else {
    // Not logged in, redirect.
    return res.redirect('/login');
  }
});

app.get('/v1/assign', (req, res) => {
  // First, fetch a mathing user with the user secret.
  db.users.findOne({secret: req.query.user}, (err, user) => {
    if (err) {
      res.status(500);
    } else if (!user) {
      res.status(400).send({status: 'err', msg: 'Bad user token.'});
    } else {
      // Then, fetch a matching user with the user secret.
      db.repos.findOne({secret: req.query.repo}, (err, repo) => {
        if (err) {
          res.status(500);
        } else if (!repo) {
          res.status(400).send({status: 'err', msg: 'Bad repo token.'});
        } else {
          // Totally authorized at this point, so just pick someone to assign the PR to.
          let assignees = [_.sample(repo.assignees)];
          let prNumber = 1;

          // Assign a user to a PR
          request({
            method: 'POST',
            url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${prNumber}/assignees`,
            body: JSON.stringify({assignees}),
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'User-Agent': 'assignme',
              'Authorization': `Bearer ${user.token}`,
            },
          }, (err, resp, body) => {
            if (err) {
              res.status(500).send(body);
            } else if (resp.statusCode >= 200 && resp.statusCode < 300) {
              res.send({
                status: 'ok',
                assignees,
                msg: `Assigned ${assignees} to pull request ${prNumber}`,
              });
            } else {
              res.status(resp.statusCode).send(body);
            }
          });
        }
      });
    }
  });
});

app.listen(process.env.PORT || 4000);

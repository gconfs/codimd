'use strict'

const Router = require('express').Router
const passport = require('passport')
const OidcStrategy = require('@passport-next/passport-openidconnect').Strategy;
const config = require('../../config')
const models = require('../../models')
const logger = require('../../logger')
const {urlencodedParser} = require('../../utils')
const {setReturnToFromReferer} = require('../utils')

let openIDAuth = module.exports = Router()

passport.use('oidc', new OidcStrategy({
	issuer: 'https://cri.epita.fr',
	authorizationURL: 'https://cri.epita.fr/authorize',
	tokenURL: 'https://cri.epita.fr/token',
	userInfoURL: 'https://cri.epita.fr/userinfo',
	clientID: config.epita.clientID,
	clientSecret: config.epita.clientSecret,
	callbackURL: 'https://pad.gconfs.fr/auth/oidc/callback',
	scope: 'openid profile epita'
}, (issuer, sub, profile, accessToken, refreshToken, done) => {

	profile = profile._json

	var epita = {
		id: profile.uid,
		username: profile.login,
		displayName: profile.name,
		emails: [profile.login + '@epita.fr'],
		avatarUrl: 'https://photos.cri.epita.fr/square/' + profile.login,
		profileUrl: 'https://cri.epita.fr/accounts/users/' + profile.login,
		promo: profile.promo,
		provider: 'epita'
	}

	var stringifiedProfile = JSON.stringify(epita)
	models.User.findOrCreate({
		where: {
			email: epita.emails[0]
		},
		defaults: {
			profileid: epita.username,
			profile: stringifiedProfile,
			accessToken: accessToken,
			refreshToken: refreshToken
		}
	}).spread(function (user, created) {
		if (user) {
			var needSave = false
			if (user.profile !== stringifiedProfile) {
				user.profile = stringifiedProfile
				needSave = true
			}

			if (user.accessToken !== accessToken || user.refreshToken !== refreshToken) {
				user.accessToken = accessToken
				user.refreshToken = refreshToken
				needSave = true
			}

			if (needSave) {
				user.save().then(function () {
					if (config.debug) { logger.info('user login: ' + user.id) }
					return done(null, user)
				})
			} else {
				if (config.debug) { logger.info('user login: ' + user.id) }
				return done(null, user)
			}
		}
	}).catch(function (err) {
		logger.error('auth callback failed: ' + err)
		return done(err, null)
	})
}));

openIDAuth.get('/auth/epita', urlencodedParser, function (req, res, next) {
	setReturnToFromReferer(req)
	passport.authenticate('oidc')(req, res, next)
})

openIDAuth.get('/auth/oidc/callback',
	passport.authenticate('oidc', {
		successReturnToOrRedirect: config.serverurl + '/',
		failureRedirect: config.serverurl + '/'
	})
)

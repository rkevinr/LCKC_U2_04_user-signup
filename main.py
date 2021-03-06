#!/usr/bin/env python

import webapp2
import cgi
import re


def build_page(username, email, username_error, password_error,
                    verify_password_error, email_error):
    
    page_top = '''
    <!DOCTYPE html>
    
    <html>
      <head>
        <style>
          td.prompt { text-align: right; }
          span.error { color: red; }
        </style>
      </head>
      <body>
      <h1>User Sign-up</h1>
        <form method="post">
          <table>
            <tr>
    '''
    username_row = '''
              <td class="prompt"><label for="username">Username</label></td>
              <td>
                <input name="username" type="text" value="''' + username + '''">
                <span class="error">''' + username_error + '''</span>
              </td>
            </tr>'''
    
    password_row = '''
            <tr>
              <td class="prompt"><label for="password">Password</label></td>
              <td>
                <input name="password" type="password">
                <span class="error">''' + password_error + '''</span>
              </td>
            </tr>'''
    
    verify_password_row = '''
            <tr>
              <td class="prompt"><label for="verify">Verify Password</label></td>
              <td>
                <input name="verify" type="password">
                <span class="error">''' + verify_password_error + '''</span>
              </td>
            </tr>'''
    
    email_row = '''
            <tr>
              <td class="prompt"><label for="email">Email (optional)</label></td>
              <td>
                <input name="email" type="email" value="''' + email + '''">
                <span class="error">''' + email_error + '''</span>
              </td>
            </tr>'''
    
    page_bottom = '''
            <tr>
              <td></td>
              <td><input type="submit"></td>
            </tr>
          </table>
        </form>
      </body>
    </html>
    '''

    return (page_top + username_row + password_row + 
            verify_password_row + email_row + page_bottom)


class WelcomeHandler(webapp2.RequestHandler):

    def get(self):
        self.response.write('<h2>Welcome, ' + self.request.get("username") + '!</h2>')


def is_valid_field(field_name, field_regex):
    if re.match(field_regex, field_name):
        return True
    return False


class MainHandler(webapp2.RequestHandler):

    def post(self):
        USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
        PASS_RE = re.compile(r'^.{3,20}$')
        EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

        ERROR_USER = 'Please enter a valid username.'
        ERROR_PASSWORD = 'Enter a valid password (3-20 characters).'
        ERROR_VERIFY_PASSWORD = 'Passwords don\'t match.'
        ERROR_EMAIL_ADDR = 'Please enter a valid email address.'

        err_user = ''
        err_passwd = ''
        err_verify_passwd = ''
        err_email_addr = ''

        # the form itself COULD specify "required" for the required fields,
        #   elim'g need to check PRESENCE of those fields, just their validity
        username = self.request.get("username")         
        password = self.request.get("password")         
        verify_password = self.request.get("verify")         
        email = self.request.get("email") 

        all_fields_valid = True

        stripped_username = username.rstrip().lstrip()
        if not is_valid_field(stripped_username, USER_RE): 
            err_user = ERROR_USER
            all_fields_valid = False

        stripped_password = password.rstrip().lstrip()
        stripped_verify_password = verify_password.rstrip().lstrip()

        if not is_valid_field(stripped_password, PASS_RE):
            err_passwd = ERROR_PASSWORD
            all_fields_valid = False
        
        # if not is_valid_field(stripped_verify_password, PASS_RE):
        #    err_verify_passwd = ERROR_PASSWORD
        if stripped_verify_password != stripped_password:
            err_verify_passwd = ERROR_VERIFY_PASSWORD
            all_fields_valid = False

        stripped_email_addr = email.rstrip().lstrip()
        if not (is_valid_field(stripped_email_addr, EMAIL_RE) or
                        len(stripped_email_addr) == 0):
            err_email_addr = ERROR_EMAIL_ADDR
            all_fields_valid = False

        if all_fields_valid:
            self.redirect('/welcome?username=' + stripped_username)
        else:
            updated_page = build_page(stripped_username, stripped_email_addr,
                                        err_user, err_passwd, err_verify_passwd,
                                            err_email_addr)
            self.response.write(updated_page)


    def get(self):
        starter_page = build_page("", "", "", "", "", "")
        self.response.write(starter_page)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)

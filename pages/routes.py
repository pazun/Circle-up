from flask import Blueprint, render_template

pages = Blueprint('pages', __name__)

@pages.route('/faq')
def faq():
    return render_template('faq.html')

@pages.route('/about')
def about():
    return render_template('about.html')
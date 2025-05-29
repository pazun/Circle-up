from flask import Blueprint, render_template

routes = Blueprint('routes', __name__)

@routes.route('/faq')
def faq():
    return render_template('faq.html')
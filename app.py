from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)


@app.context_processor
def inject_current_year():
    """Provide current_year to all templates to avoid relying on a non-existent 'date' filter."""
    return {"current_year": datetime.utcnow().year}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        # In a real app you'd store/send the message. For this template we just show a thank-you.
        return render_template('contact.html', submitted=True, name=name)
    return render_template('contact.html', submitted=False)


if __name__ == '__main__':
    app.run(debug=True)

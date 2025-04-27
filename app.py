from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Income, FixedExpense, BudgetCategory, Expense

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///budget.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        # Handle income
        if 'income' in request.form:
            amount = float(request.form['income'])
            income = Income.query.filter_by(user_id=current_user.id).first()
            if income:
                income.amount = amount
            else:
                income = Income(amount=amount, user_id=current_user.id)
                db.session.add(income)
        # Handle fixed expenses
        elif 'fixed_expense_name' in request.form:
            name = request.form['fixed_expense_name']
            amount = float(request.form['fixed_expense_amount'])
            fixed = FixedExpense(name=name, amount=amount, user_id=current_user.id)
            db.session.add(fixed)
        # Handle budget categories
        elif 'category_name' in request.form:
            name = request.form['category_name']
            amount = float(request.form['category_amount'])
            category = BudgetCategory(name=name, amount=amount, user_id=current_user.id)
            db.session.add(category)
        db.session.commit()
    income = Income.query.filter_by(user_id=current_user.id).first()
    fixed_expenses = FixedExpense.query.filter_by(user_id=current_user.id).all()
    categories = BudgetCategory.query.filter_by(user_id=current_user.id).all()
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', income=income, fixed_expenses=fixed_expenses, categories=categories, expenses=expenses)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        name = request.form['expense_name']
        amount = float(request.form['expense_amount'])
        category_id = int(request.form['category_id'])
        expense = Expense(name=name, amount=amount, category_id=category_id, user_id=current_user.id)
        db.session.add(expense)
        db.session.commit()
        return redirect(url_for('dashboard'))
    categories = BudgetCategory.query.filter_by(user_id=current_user.id).all()
    return render_template('add_expense.html', categories=categories)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
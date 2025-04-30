from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Income, FixedExpense, BudgetCategory, Expense
import os
from datetime import datetime, timedelta
import secrets
import sendgrid
from sendgrid.helpers.mail import Mail
from urllib.parse import urlencode

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///budget.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize SendGrid
sg = sendgrid.SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')

# Initialize database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_reset_token():
    return secrets.token_urlsafe(32)

def send_reset_email(user):
    token = generate_reset_token()
    user.reset_token = token
    user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    db.session.commit()

    reset_url = url_for('reset_password', token=token, _external=True)
    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=user.email,
        subject='Password Reset Request for Budget Freedom',
        html_content=f'''
        <p>You have requested to reset your password for Budget Freedom.</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>This link will expire in 1 hour. If you did not request a password reset, please ignore this email.</p>
        '''
    )
    try:
        response = sg.send(message)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def index():
    return render_template('templates_index')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not email or not password:
            flash('Email and password are required.')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created! Please set up your income and budget.')
        return redirect(url_for('dashboard'))
    return render_template('templates_register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not email or not password:
            flash('Email and password are required.')
            return redirect(url_for('login'))
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('templates_login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        try:
            # Handle income
            if 'income' in request.form:
                amount = float(request.form['income'])
                if amount < 0:
                    flash('Income cannot be negative.')
                    return redirect(url_for('dashboard'))
                income = Income.query.filter_by(user_id=current_user.id).first()
                if income:
                    income.amount = amount
                else:
                    income = Income(amount=amount, user_id=current_user.id)
                    db.session.add(income)
            # Handle fixed expenses
            elif 'fixed_expense_name' in request.form:
                name = request.form['fixed_expense_name'].strip()
                amount = float(request.form['fixed_expense_amount'])
                if not name:
                    flash('Fixed expense name is required.')
                    return redirect(url_for('dashboard'))
                if amount < 0:
                    flash('Fixed expense amount cannot be negative.')
                    return redirect(url_for('dashboard'))
                fixed = FixedExpense(name=name, amount=amount, user_id=current_user.id)
                db.session.add(fixed)
            # Handle budget categories
            elif 'category_name' in request.form:
                name = request.form['category_name'].strip()
                amount = float(request.form['category_amount'])
                if not name:
                    flash('Category name is required.')
                    return redirect(url_for('dashboard'))
                if amount < 0:
                    flash('Category budget cannot be negative.')
                    return redirect(url_for('dashboard'))
                category = BudgetCategory(name=name, amount=amount, user_id=current_user.id)
                db.session.add(category)
            db.session.commit()
            flash('Data updated successfully.')
        except ValueError:
            flash('Invalid input. Please enter valid numbers.')
        return redirect(url_for('dashboard'))

    # Fetch data
    income = Income.query.filter_by(user_id=current_user.id).first()
    fixed_expenses = FixedExpense.query.filter_by(user_id=current_user.id).all()
    categories = BudgetCategory.query.filter_by(user_id=current_user.id).all()
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # Calculate remaining budget for each category
    category_budgets = []
    for category in categories:
        total_expenses = sum(expense.amount for expense in category.expenses) if category.expenses else 0.0
        remaining = category.amount - total_expenses
        category_budgets.append({
            'id': category.id,
            'name': category.name,
            'budget': category.amount,
            'spent': total_expenses,
            'remaining': remaining
        })

    # Calculate total remaining funds for the month
    total_income = income.amount if income else 0.0
    total_fixed_expenses = sum(expense.amount for expense in fixed_expenses)
    total_category_budgets = sum(category.amount for category in categories)
    remaining_funds = total_income - (total_fixed_expenses + total_category_budgets)

    return render_template('templates_dashboard',
                         income=income,
                         fixed_expenses=fixed_expenses,
                         category_budgets=category_budgets,
                         expenses=expenses,
                         total_income=total_income,
                         total_fixed_expenses=total_fixed_expenses,
                         total_category_budgets=total_category_budgets,
                         remaining_funds=remaining_funds)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    categories = BudgetCategory.query.filter_by(user_id=current_user.id).all()
    categories_with_remaining = [
        {
            'id': category.id,
            'name': category.name,
            'remaining': category.amount - sum(expense.amount for expense in category.expenses) if category.expenses else category.amount
        }
        for category in categories
    ]
    if request.method == 'POST':
        try:
            name = request.form['expense_name'].strip()
            amount = float(request.form['expense_amount'])
            category_id = int(request.form['category_id'])
            if not name:
                flash('Expense name is required.')
                return redirect(url_for('add_expense'))
            if amount < 0:
                flash('Expense amount cannot be negative.')
                return redirect(url_for('add_expense'))
            if not any(category.id == category_id for category in categories):
                flash('Invalid category selected.')
                return redirect(url_for('add_expense'))
            expense = Expense(name=name, amount=amount, category_id=category_id, user_id=current_user.id)
            db.session.add(expense)
            db.session.commit()
            flash('Expense added successfully.')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid input. Please enter a valid amount.')
    if not categories:
        flash('Please add a budget category first.')
        return redirect(url_for('dashboard'))
    return render_template('templates_add_expense', categories=categories_with_remaining)

@app.route('/edit_expense/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    expense = Expense.query.get_or_404(id)
    if expense.user_id != current_user.id:
        flash('You can only edit your own expenses.')
        return redirect(url_for('dashboard'))
    categories = BudgetCategory.query.filter_by(user_id=current_user.id).all()
    categories_with_remaining = [
        {
            'id': category.id,
            'name': category.name,
            'remaining': category.amount - sum(expense.amount for expense in category.expenses) if category.expenses else category.amount
        }
        for category in categories
    ]
    if request.method == 'POST':
        try:
            name = request.form['expense_name'].strip()
            amount = float(request.form['expense_amount'])
            category_id = int(request.form['category_id'])
            if not name:
                flash('Expense name is required.')
                return redirect(url_for('edit_expense', id=id))
            if amount < 0:
                flash('Expense amount cannot be negative.')
                return redirect(url_for('edit_expense', id=id))
            if not any(category.id == category_id for category in categories):
                flash('Invalid category selected.')
                return redirect(url_for('edit_expense', id=id))
            expense.name = name
            expense.amount = amount
            expense.category_id = category_id
            db.session.commit()
            flash('Expense updated successfully.')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid input. Please enter a valid amount.')
    return render_template('templates_edit_expense', expense=expense, categories=categories_with_remaining)

@app.route('/delete_expense/<int:id>', methods=['POST'])
@login_required
def delete_expense(id):
    expense = Expense.query.get_or_404(id)
    if expense.user_id != current_user.id:
        flash('You can only delete your own expenses.')
        return redirect(url_for('dashboard'))
    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/edit_fixed_expense/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_fixed_expense(id):
    fixed_expense = FixedExpense.query.get_or_404(id)
    if fixed_expense.user_id != current_user.id:
        flash('You can only edit your own fixed expenses.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            name = request.form['fixed_expense_name'].strip()
            amount = float(request.form['fixed_expense_amount'])
            if not name:
                flash('Fixed expense name is required.')
                return redirect(url_for('edit_fixed_expense', id=id))
            if amount < 0:
                flash('Fixed expense amount cannot be negative.')
                return redirect(url_for('edit_fixed_expense', id=id))
            fixed_expense.name = name
            fixed_expense.amount = amount
            db.session.commit()
            flash('Fixed expense updated successfully.')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid input. Please enter a valid amount.')
    return render_template('templates_edit_fixed_expense', fixed_expense=fixed_expense)

@app.route('/delete_fixed_expense/<int:id>', methods=['POST'])
@login_required
def delete_fixed_expense(id):
    fixed_expense = FixedExpense.query.get_or_404(id)
    if fixed_expense.user_id != current_user.id:
        flash('You can only delete your own fixed expenses.')
        return redirect(url_for('dashboard'))
    db.session.delete(fixed_expense)
    db.session.commit()
    flash('Fixed expense deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/edit_category/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_category(id):
    category = BudgetCategory.query.get_or_404(id)
    if category.user_id != current_user.id:
        flash('You can only edit your own categories.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            name = request.form['category_name'].strip()
            amount = float(request.form['category_amount'])
            if not name:
                flash('Category name is required.')
                return redirect(url_for('edit_category', id=id))
            if amount < 0:
                flash('Category budget cannot be negative.')
                return redirect(url_for('edit_category', id=id))
            category.name = name
            category.amount = amount
            db.session.commit()
            flash('Category updated successfully.')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid input. Please enter a valid amount.')
    return render_template('templates_edit_category', category=category)

@app.route('/delete_category/<int:id>', methods=['POST'])
@login_required
def delete_category(id):
    category = BudgetCategory.query.get_or_404(id)
    if category.user_id != current_user.id:
        flash('You can only delete your own categories.')
        return redirect(url_for('dashboard'))
    if category.expenses:
        flash('Cannot delete category with associated expenses.')
        return redirect(url_for('dashboard'))
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.')
            return redirect(url_for('change_password'))

        # Verify current password
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.')
            return redirect(url_for('change_password'))

        # Check if new password matches confirmation
        if new_password != confirm_password:
            flash('New password and confirmation do not match.')
            return redirect(url_for('change_password'))

        # Check if new password is different from the current one
        if check_password_hash(current_user.password, new_password):
            flash('New password must be different from the current password.')
            return redirect(url_for('change_password'))

        # Update the password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully.')
        return redirect(url_for('dashboard'))

    return render_template('templates_change_password')

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            if send_reset_email(user):
                flash('A password reset email has been sent to your email address.')
            else:
                flash('There was an error sending the reset email. Please try again later.')
        else:
            flash('Email not found. Please register or try again.')
        return redirect(url_for('login'))
    return render_template('templates_reset_password_request')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('Invalid or expired reset link.')
        return redirect(url_for('login'))
    if user.reset_token_expiration < datetime.utcnow():
        flash('The reset link has expired.')
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not new_password or not confirm_password:
            flash('All fields are required.')
            return redirect(url_for('reset_password', token=token))
        if new_password != confirm_password:
            flash('New password and confirmation do not match.')
            return redirect(url_for('reset_password', token=token))
        if check_password_hash(user.password, new_password):
            flash('New password must be different from the current password.')
            return redirect(url_for('reset_password', token=token))
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('Your password has been reset successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('templates_reset_password', token=token)

@app.route('/clear_expenses', methods=['POST'])
@login_required
def clear_expenses():
    # Delete all non-fixed expenses for the current user
    Expense.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('All non-fixed expenses have been cleared.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, filedialog, ttk
import sqlite3
import hashlib
import secrets
from practice import CarPark

# ============================================================================
# DEFAULT ADMIN CREDENTIALS - USED ONLY ON FIRST RUN TO SEED USER TABLE
# CHANGE THESE BEFORE FIRST RUN TO SET YOUR OWN DEFAULT ADMIN ACCOUNT.
# ============================================================================
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
# ============================================================================


def hash_password(password: str) -> str:
    """Create a salted password hash using SHA-256."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against the stored salted hash."""
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, hashed = stored_hash.split("$", 1)
    candidate = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return secrets.compare_digest(candidate, hashed)


class UserManager:
    """Simple user manager that stores accounts inside the same SQLite DB."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_user_table()
        self._ensure_default_admin()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_user_table(self):
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _ensure_default_admin(self):
        if not self.get_user(DEFAULT_ADMIN_USERNAME):
            self.create_user(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, role="admin")

    # ------------------------------------------------------------------ API --
    def get_user(self, username: str):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT username, password_hash, role FROM users WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()
            if row:
                return {"username": row[0], "password_hash": row[1], "role": row[2]}
            return None
        finally:
            conn.close()

    def list_users(self):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT username, role, created_at FROM users ORDER BY created_at ASC"
            )
            return [
                {"username": row[0], "role": row[1], "created_at": row[2]}
                for row in cur.fetchall()
            ]
        finally:
            conn.close()

    def create_user(self, username: str, password: str, role: str = "user"):
        username = (username or "").strip()
        if not username:
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")
        role = (role or "user").lower()
        if role not in ("user", "admin"):
            raise ValueError("Role must be 'user' or 'admin'.")
        if self.get_user(username):
            raise ValueError("Username already exists.")

        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role),
            )
            conn.commit()
        finally:
            conn.close()

    def authenticate(self, username: str, password: str) -> bool:
        user = self.get_user(username)
        if not user:
            return False
        return verify_password(password, user["password_hash"])

    def change_password(self, username: str, new_password: str):
        if not new_password:
            raise ValueError("Password cannot be empty.")
        if not self.get_user(username):
            raise ValueError("User does not exist.")
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            conn.commit()
        finally:
            conn.close()

    def reset_password(self, target_username: str, new_password: str):
        self.change_password(target_username, new_password)

    def delete_user(self, target_username: str):
        if not self.get_user(target_username):
            raise ValueError("User does not exist.")
        if self.is_last_admin(target_username):
            raise ValueError("Cannot delete the last admin account.")
        conn = self._connect()
        try:
            conn.execute("DELETE FROM users WHERE username = ?", (target_username,))
            conn.commit()
        finally:
            conn.close()

    def is_admin(self, username: str) -> bool:
        user = self.get_user(username)
        return bool(user and user.get("role") == "admin")

    def is_last_admin(self, username: str) -> bool:
        user = self.get_user(username)
        if not user or user.get("role") != "admin":
            return False
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            count = cur.fetchone()[0]
            return count == 1
        finally:
            conn.close()


class CarParkGUI:
    def __init__(self, root, user_manager: UserManager, current_user: str):
        self.root = root
        self.user_manager = user_manager
        self.current_user = current_user
        self.db_path = self.user_manager.db_path
        root.title(f'Car Park Manager — Logged in as {self.current_user}')

        # Build application menus (account management, admin tools)
        self._build_menus()

        # Top frame: capacity
        top = tk.Frame(root)
        top.pack(fill='x', padx=8, pady=6)

        tk.Label(top, text='Capacity:').pack(side='left')
        self.capacity_var = tk.IntVar(value=10)
        self.capacity_entry = tk.Entry(top, width=6, textvariable=self.capacity_var)
        self.capacity_entry.pack(side='left', padx=(4, 8))
        # Rate per hour control
        tk.Label(top, text='Rate/hr:').pack(side='left')
        self.rate_var = tk.DoubleVar(value=2.0)
        self.rate_entry = tk.Entry(top, width=6, textvariable=self.rate_var)
        self.rate_entry.pack(side='left', padx=(4, 8))
        tk.Button(top, text='Set Rate', command=self.set_rate).pack(side='left')

        tk.Button(top, text='Create Park', command=self.create_park).pack(side='left')
        # Search field (plate or spot)
        tk.Label(top, text='Search:').pack(side='left', padx=(12,0))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, width=20, textvariable=self.search_var)
        self.search_entry.pack(side='left', padx=(4,4))
        tk.Button(top, text='Search', command=self.perform_search).pack(side='left')

        # Middle frame: controls
        ctrls = tk.Frame(root)
        ctrls.pack(fill='x', padx=8, pady=6)

        tk.Button(ctrls, text='Park Car (P)', width=12, command=self.park_car).pack(side='left')
        tk.Button(ctrls, text='Remove Car (R)', width=12, command=self.remove_car).pack(side='left', padx=6)
        tk.Button(ctrls, text='View Cars (V)', width=12, command=self.view_cars).pack(side='left')
        tk.Button(ctrls, text='Available (A)', width=12, command=self.show_available).pack(side='left', padx=6)
        tk.Button(ctrls, text='Transactions', width=12, command=self.view_transactions).pack(side='left', padx=6)
        tk.Button(ctrls, text='Print Invoice', width=12, command=self.print_invoice).pack(side='left', padx=6)
        tk.Button(ctrls, text='Daily Invoice', width=12, command=self.daily_invoice).pack(side='left', padx=6)
        tk.Button(ctrls, text='Save', width=8, command=self.save_park).pack(side='right', padx=6)
        tk.Button(ctrls, text='Load', width=8, command=self.load_park).pack(side='right')
        tk.Button(ctrls, text='Exit (Q)', width=8, command=root.quit).pack(side='right', padx=(6,0))

        # List + log
        body = tk.Frame(root)
        body.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Full width: prettier table for current parked cars
        left_frame = tk.LabelFrame(body, text='Currently Parked Cars', font=('Arial', 10, 'bold'), padx=0, pady=0)
        left_frame.pack(side='left', fill='both', expand=True)

        cols = ('spot', 'plate', 'time_in', 'time_out', 'comments')
        self.tree = ttk.Treeview(left_frame, columns=cols, show='headings', height=25)
        self.tree.heading('spot', text='Spot')
        self.tree.heading('plate', text='Registration')
        self.tree.heading('time_in', text='Time In')
        self.tree.heading('time_out', text='Time Out')
        self.tree.heading('comments', text='Comments')
        self.tree.column('spot', width=50, anchor='center')
        self.tree.column('plate', width=100, anchor='w')
        self.tree.column('time_in', width=160, anchor='w')
        self.tree.column('time_out', width=160, anchor='w')
        self.tree.column('comments', width=200, anchor='w')

        vsb = ttk.Scrollbar(left_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click to edit comments
        self.tree.bind('<Double-1>', self.on_tree_double_click)

        # initialize
        self.park = None
        # db_path is already set from user_manager.db_path above
        self.auto_load_on_startup()

        # keyboard shortcuts
        root.bind('<p>', lambda e: self.park_car())
        root.bind('<P>', lambda e: self.park_car())
        root.bind('<r>', lambda e: self.remove_car())
        root.bind('<R>', lambda e: self.remove_car())
        root.bind('<v>', lambda e: self.view_cars())
        root.bind('<V>', lambda e: self.view_cars())
        root.bind('<a>', lambda e: self.show_available())
        root.bind('<A>', lambda e: self.show_available())
        root.bind('<q>', lambda e: root.quit())
        root.bind('<Q>', lambda e: root.quit())
        # Enter key triggers search when focus is on search entry
        self.search_entry.bind('<Return>', lambda e: self.perform_search())
        # Enter key on rate_entry applies the rate
        self.rate_entry.bind('<Return>', lambda e: self.set_rate())
        
        # auto-save on exit
        root.protocol('WM_DELETE_WINDOW', self.on_exit)

    def _build_menus(self):
        menubar = tk.Menu(self.root)

        account_menu = tk.Menu(menubar, tearoff=0)
        account_menu.add_command(label='Change Password', command=self.change_password_dialog)
        account_menu.add_separator()
        account_menu.add_command(label='Logout', command=self.logout)
        menubar.add_cascade(label='Account', menu=account_menu)

        if self.user_manager.is_admin(self.current_user):
            admin_menu = tk.Menu(menubar, tearoff=0)
            admin_menu.add_command(label='Manage Users', command=self.manage_users_dialog)
            menubar.add_cascade(label='Admin', menu=admin_menu)

        self.root.config(menu=menubar)

    def create_park(self):
        try:
            cap = int(self.capacity_entry.get())
            if cap <= 0:
                raise ValueError()
        except Exception:
            messagebox.showerror('Error', 'Please enter a positive integer capacity')
            return

        self.park = CarPark(cap)
        # apply current rate
        try:
            self.park.rate_per_hour = float(self.rate_var.get())
        except Exception:
            self.park.rate_per_hour = getattr(self.park, 'rate_per_hour', 2.0)
        self.refresh_list()

    def refresh_list(self):
        # Clear tree and repopulate with current parked cars
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.park or not self.park.parked_cars:
            return
        
        for spot in range(1, self.park.capacity + 1):
            rec = self.park.parked_cars.get(spot)
            if rec:
                plate = str(rec.get('plate', ''))
                time_in = str(rec.get('time_in', ''))
                time_in_short = time_in[:19] if time_in else ''
                
                # get comments from parked car record (for currently parked cars)
                comments = str(rec.get('comments', ''))
                time_out_short = ''
                
                # also check transactions for time_out if it was removed and re-parked
                for tx in reversed(self.park.transactions):
                    if tx.get('spot') == spot:
                        time_out = str(tx.get('time_out', ''))
                        time_out_short = time_out[:19] if time_out else ''
                        # prefer transaction comments if present
                        if tx.get('comments'):
                            comments = str(tx.get('comments', ''))
                        break
                
                self.tree.insert('', 'end', values=(str(spot), plate, time_in_short, time_out_short, comments))

    def on_tree_double_click(self, event):
        """Handle double-click on tree to edit comments."""
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not item or col != '#5':  # only allow editing comments column (column 5)
            return
        
        vals = self.tree.item(item, 'values')
        try:
            spot = int(vals[0])
        except (ValueError, IndexError):
            return
        
        # find or create transaction for this spot
        tx = None
        for t in reversed(self.park.transactions):
            if t.get('spot') == spot:
                tx = t
                break
        
        # if no transaction but car is parked, create a placeholder transaction for editing
        if not tx:
            rec = self.park.parked_cars.get(spot)
            if rec:
                tx = {
                    'spot': spot,
                    'plate': rec.get('plate', ''),
                    'time_in': rec.get('time_in', ''),
                    'time_out': '',
                    'amount': 0,
                    'paid': False,
                    'comments': rec.get('comments', '')
                }
                # Add this transaction to the list so comments get saved
                self.park.transactions.append(tx)
        
        if tx:
            self.edit_transaction_comments(tx)

    def edit_transaction_comments(self, tx):
        """Open a dialog to edit transaction comments."""
        dlg = tk.Toplevel(self.root)
        dlg.title(f'Edit Comments — Spot {tx.get("spot")}')
        dlg.geometry('500x320')
        dlg.resizable(False, False)

        title = tk.Label(dlg, text=f'Edit Comments — Spot {tx.get("spot")} ({tx.get("plate")})', font=('Arial', 12, 'bold'))
        title.pack(pady=12)

        # Comments text area in a box
        comments_frame = tk.LabelFrame(dlg, text='Comments', font=('Arial', 10, 'bold'), padx=12, pady=10)
        comments_frame.pack(fill='both', expand=True, padx=20, pady=6)
        
        comments_text = tk.Text(comments_frame, font=('Arial', 10), height=10, width=50, wrap='word')
        comments_text.pack(fill='both', expand=True)
        comments_text.insert('1.0', tx.get('comments', ''))

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', padx=20, pady=12, side='bottom')

        def save_comments():
            comment_text = comments_text.get('1.0', 'end').strip()
            tx['comments'] = comment_text
            
            # also save to parked car record if it exists
            spot = tx.get('spot')
            if spot in self.park.parked_cars:
                self.park.parked_cars[spot]['comments'] = comment_text
            
            # persist to database
            try:
                self.park.save_to_db(self.db_path)
                messagebox.showinfo('Success', 'Comments saved successfully')
            except Exception as e:
                messagebox.showerror('Save Error', f'Failed to save: {e}')
            
            self.refresh_list()
            dlg.destroy()

        tk.Button(btn_frame, text='Save', width=12, bg='#4CAF50', fg='white', font=('Arial', 10), command=save_comments).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Cancel', width=12, bg='#f44336', fg='white', font=('Arial', 10), command=dlg.destroy).pack(side='left', padx=4)

    def park_car(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return
        
        # Create a custom dialog with prettier form
        dlg = tk.Toplevel(self.root)
        dlg.title('Park Car')
        dlg.geometry('400x250')
        dlg.resizable(False, False)

        # Title
        title = tk.Label(dlg, text='Park a New Car', font=('Arial', 14, 'bold'))
        title.pack(pady=16)

        # License Plate field in a box
        plate_frame = tk.LabelFrame(dlg, text='License Plate', font=('Arial', 10, 'bold'), padx=12, pady=12)
        plate_frame.pack(fill='x', padx=20, pady=8)
        
        plate_var = tk.StringVar()
        plate_entry = tk.Entry(plate_frame, textvariable=plate_var, font=('Arial', 12), width=25)
        plate_entry.pack(fill='x')
        plate_entry.focus()

        # Info label
        info = tk.Label(dlg, text='Enter the license plate number of the car to park', font=('Arial', 9), fg='gray')
        info.pack(pady=4)

        # Buttons in a box
        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', padx=20, pady=16)

        def on_park():
            plate = plate_var.get().strip()
            if not plate:
                messagebox.showwarning('Empty field', 'Please enter a license plate')
                return
            success = self.park.park_car(plate)
            if success:
                messagebox.showinfo('Success', f'Car {plate} parked successfully')
                dlg.destroy()
            else:
                messagebox.showerror('Failed', 'Car park is full!')
            self.refresh_list()

        tk.Button(btn_frame, text='Park', width=12, bg='#4CAF50', fg='white', font=('Arial', 10), command=on_park).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Cancel', width=12, bg='#f44336', fg='white', font=('Arial', 10), command=dlg.destroy).pack(side='left', padx=4)

    def remove_car(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return
        
        # Create a custom dialog
        dlg = tk.Toplevel(self.root)
        dlg.title('Remove Car')
        dlg.geometry('400x250')
        dlg.resizable(False, False)

        title = tk.Label(dlg, text='Remove a Car', font=('Arial', 14, 'bold'))
        title.pack(pady=16)

        # Spot number field in a box
        spot_frame = tk.LabelFrame(dlg, text='Spot Number', font=('Arial', 10, 'bold'), padx=12, pady=12)
        spot_frame.pack(fill='x', padx=20, pady=8)
        
        spot_var = tk.StringVar()
        spot_entry = tk.Entry(spot_frame, textvariable=spot_var, font=('Arial', 12), width=25)
        spot_entry.pack(fill='x')
        spot_entry.focus()

        info = tk.Label(dlg, text='Enter the spot number to remove', font=('Arial', 9), fg='gray')
        info.pack(pady=4)

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', padx=20, pady=16)

        def on_remove():
            try:
                spot = int(spot_var.get())
            except ValueError:
                messagebox.showwarning('Invalid', 'Please enter a valid spot number')
                return
            result = self.park.remove_car(spot)
            if not result:
                messagebox.showerror('Failed', f'No car at spot {spot}')
                return
            self.show_transaction_dialog(result)
            self.refresh_list()
            dlg.destroy()

        tk.Button(btn_frame, text='Remove', width=12, bg='#FF9800', fg='white', font=('Arial', 10), command=on_remove).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Cancel', width=12, bg='#f44336', fg='white', font=('Arial', 10), command=dlg.destroy).pack(side='left', padx=4)

    def view_cars(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return

        # update main list
        self.refresh_list()

        # Create a clean table popup showing all spots with details
        win = tk.Toplevel(self.root)
        win.title('Parked Cars — Table View')
        win.geometry('700x400')

        # include transaction columns: time_out, amount, paid
        cols = ('spot', 'plate', 'time_in', 'time_out', 'amount', 'paid')
        tree = ttk.Treeview(win, columns=cols, show='headings')
        tree.heading('spot', text='Spot')
        tree.heading('plate', text='License Plate')
        tree.heading('time_in', text='Time In (GMT+7)')
        tree.heading('time_out', text='Time Out')
        tree.heading('amount', text='Amount')
        tree.heading('paid', text='Paid')
        tree.column('spot', width=60, anchor='center')
        tree.column('plate', width=140, anchor='w')
        tree.column('time_in', width=200, anchor='w')
        tree.column('time_out', width=140, anchor='w')
        tree.column('amount', width=80, anchor='e')
        tree.column('paid', width=40, anchor='center')

        vsb = ttk.Scrollbar(win, orient='vertical', command=tree.yview)
        hsb = ttk.Scrollbar(win, orient='horizontal', command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        win.grid_rowconfigure(0, weight=1)
        win.grid_columnconfigure(0, weight=1)

        # Populate rows (show all spots 1..capacity)
        for spot in range(1, self.park.capacity + 1):
            rec = self.park.parked_cars.get(spot)
            if rec:
                plate = str(rec.get('plate', ''))
                time_in = str(rec.get('time_in', ''))
            else:
                plate = ''
                time_in = ''

            # find most recent transaction for this spot (if any)
            time_out = ''
            amount = ''
            paid_flag = ''
            for tx in reversed(self.park.transactions):
                if tx.get('spot') == spot:
                    time_out = str(tx.get('time_out', ''))
                    amount = str(tx.get('amount', ''))
                    paid_flag = '✓' if tx.get('paid') else ''
                    break

            tree.insert('', 'end', values=(str(spot), plate, time_in, time_out, amount, paid_flag))

        # define refresh function for the table view
        def refresh_tree_data():
            """Refresh all rows in the tree with current data."""
            # clear all items
            for item in tree.get_children():
                tree.delete(item)
            # repopulate with fresh data
            for spot in range(1, self.park.capacity + 1):
                rec = self.park.parked_cars.get(spot)
                plate = ''
                time_in = ''
                
                # if car is still parked, get data from parked_cars
                if rec:
                    plate = str(rec.get('plate', ''))
                    time_in = str(rec.get('time_in', ''))

                # find most recent transaction for this spot (if any)
                time_out = ''
                amount = ''
                paid_flag = ''
                for tx in reversed(self.park.transactions):
                    if tx.get('spot') == spot:
                        time_out = str(tx.get('time_out', ''))
                        amount = str(tx.get('amount', ''))
                        paid_flag = '✓' if tx.get('paid') else ''
                        # if car is not parked, get plate and time_in from transaction
                        if not rec:
                            plate = str(tx.get('plate', ''))
                            time_in = str(tx.get('time_in', ''))
                        break

                tree.insert('', 'end', values=(str(spot), plate, time_in, time_out, amount, paid_flag))

        # allow double-click to open transaction dialog / remove-or-edit
        def on_table_double_click(event):
            item = tree.identify_row(event.y)
            if not item:
                return
            vals = tree.item(item, 'values')
            try:
                spotnum = int(vals[0])
            except Exception:
                return
            # find latest transaction for spot
            tx = None
            for t in reversed(self.park.transactions):
                if t.get('spot') == spotnum:
                    tx = t
                    break

            if tx:
                self.show_transaction_dialog(tx, refresh_table_fn=refresh_tree_data)
            else:
                # if no transaction but occupied, ask to remove (create transaction)
                if spotnum in self.park.parked_cars:
                    if messagebox.askyesno('Remove', f'Remove car at spot {spotnum}?'):
                        res = self.remove_car_by_spot(spotnum)
                        if res:
                            self.show_transaction_dialog(res, refresh_table_fn=refresh_tree_data)
                else:
                    messagebox.showinfo('No data', f'No parked car or transaction for spot {spotnum}')

        tree.bind('<Double-1>', on_table_double_click)

        btn_frame = tk.Frame(win)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky='e', pady=(8,8), padx=8)
        tk.Button(btn_frame, text='Close', command=win.destroy).pack(side='right')

    def remove_car_by_spot(self, spot):
        """Remove a car programmatically by spot and return the transaction dict or False."""
        if not self.park:
            return False
        result = self.park.remove_car(spot)
        if not result:
            return False
        self.refresh_list()
        return result

    def show_available(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return
        avail = self.park.available_spots()
        messagebox.showinfo('Available Spots', f'{avail} spots available')

    def show_transaction_dialog(self, tx, refresh_table_fn=None):
        # Transaction details in a pretty form
        dlg = tk.Toplevel(self.root)
        dlg.title(f'Transaction — Spot {tx.get("spot")}')
        dlg.geometry('480x520')
        dlg.resizable(False, False)

        title = tk.Label(dlg, text=f'Transaction Details — Spot {tx.get("spot")}', font=('Arial', 14, 'bold'))
        title.pack(pady=12)

        # License Plate (read-only)
        plate_frame = tk.LabelFrame(dlg, text='License Plate', font=('Arial', 10, 'bold'), padx=12, pady=10)
        plate_frame.pack(fill='x', padx=20, pady=6)
        tk.Label(plate_frame, text=tx.get("plate"), font=('Arial', 11), fg='#333').pack(anchor='w')

        # Time In (read-only)
        timein_frame = tk.LabelFrame(dlg, text='Time In (GMT+7)', font=('Arial', 10, 'bold'), padx=12, pady=10)
        timein_frame.pack(fill='x', padx=20, pady=6)
        tk.Label(timein_frame, text=tx.get("time_in"), font=('Arial', 9), fg='#666', wraplength=350, justify='left').pack(anchor='w')

        # Time Out (read-only)
        timeout_frame = tk.LabelFrame(dlg, text='Time Out (GMT+7)', font=('Arial', 10, 'bold'), padx=12, pady=10)
        timeout_frame.pack(fill='x', padx=20, pady=6)
        tk.Label(timeout_frame, text=tx.get("time_out"), font=('Arial', 9), fg='#666', wraplength=350, justify='left').pack(anchor='w')

        # Amount (editable)
        amt_frame = tk.LabelFrame(dlg, text='Amount ($)', font=('Arial', 10, 'bold'), padx=12, pady=10)
        amt_frame.pack(fill='x', padx=20, pady=6)
        amt_var = tk.StringVar(value=str(tx.get('amount')))
        amt_entry = tk.Entry(amt_frame, textvariable=amt_var, font=('Arial', 11), width=20)
        amt_entry.pack(fill='x')

        # Paid checkbox
        paid_var = tk.BooleanVar(value=bool(tx.get('paid')))
        chk_frame = tk.LabelFrame(dlg, text='Payment Status', font=('Arial', 10, 'bold'), padx=12, pady=10)
        chk_frame.pack(fill='x', padx=20, pady=6)
        chk = tk.Checkbutton(chk_frame, text='Paid', variable=paid_var, font=('Arial', 11))
        chk.pack(anchor='w')

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', padx=20, pady=12)

        def save_and_close():
            try:
                tx['amount'] = round(float(amt_var.get()), 2)
            except Exception:
                messagebox.showwarning('Invalid', 'Please enter a valid amount')
                return
            tx['paid'] = bool(paid_var.get())
            dlg.destroy()
            if refresh_table_fn:
                refresh_table_fn()

        tk.Button(btn_frame, text='Save', width=12, bg='#4CAF50', fg='white', font=('Arial', 10), command=save_and_close).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Close', width=12, bg='#757575', fg='white', font=('Arial', 10), command=dlg.destroy).pack(side='left', padx=4)

    def print_invoice(self):
        """Print invoice for a specific transaction."""
        if not self.park or not self.park.transactions:
            messagebox.showwarning('No data', 'No transactions to print')
            return
        
        # Show dialog to select which transaction to print
        dlg = tk.Toplevel(self.root)
        dlg.title('Select Transaction to Print')
        dlg.geometry('600x300')
        
        tk.Label(dlg, text='Select a transaction to print invoice:', font=('Arial', 11, 'bold')).pack(pady=10)
        
        cols = ('index', 'spot', 'plate', 'time_in', 'time_out', 'amount')
        tree = ttk.Treeview(dlg, columns=cols, show='headings', height=12)
        tree.heading('index', text='#')
        tree.heading('spot', text='Spot')
        tree.heading('plate', text='License Plate')
        tree.heading('time_in', text='Time In')
        tree.heading('time_out', text='Time Out')
        tree.heading('amount', text='Amount')
        tree.column('index', width=30, anchor='center')
        tree.column('spot', width=40, anchor='center')
        tree.column('plate', width=100, anchor='w')
        tree.column('time_in', width=140, anchor='w')
        tree.column('time_out', width=140, anchor='w')
        tree.column('amount', width=80, anchor='e')
        
        vsb = ttk.Scrollbar(dlg, orient='vertical', command=tree.yview)
        tree.configure(yscroll=vsb.set)
        tree.pack(fill='both', expand=True, padx=8, pady=8, side='left')
        vsb.pack(side='right', fill='y')
        
        # Populate with recent transactions
        for i, tx in enumerate(reversed(self.park.transactions), 1):
            tree.insert('', 'end', values=(
                str(i),
                str(tx.get('spot', '')),
                str(tx.get('plate', '')),
                str(tx.get('time_in', ''))[:19],
                str(tx.get('time_out', ''))[:19],
                f"${tx.get('amount', 0):.2f}"
            ))
        
        def print_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning('No selection', 'Please select a transaction')
                return
            
            vals = tree.item(sel[0], 'values')
            try:
                idx = int(vals[0]) - 1
                tx_idx = len(self.park.transactions) - idx - 1
                if 0 <= tx_idx < len(self.park.transactions):
                    tx = self.park.transactions[tx_idx]
                    self._generate_invoice(tx)
                    dlg.destroy()
            except Exception as e:
                messagebox.showerror('Error', str(e))
        
        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', padx=8, pady=8)
        tk.Button(btn_frame, text='Print', width=12, bg='#2196F3', fg='white', command=print_selected).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Cancel', width=12, bg='#f44336', fg='white', command=dlg.destroy).pack(side='left', padx=4)

    def _generate_invoice(self, tx):
        """Generate and display an invoice for a single transaction."""
        from datetime import datetime
        
        invoice_text = f"""
{'='*50}
                    INVOICE
{'='*50}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Spot Number: {tx.get('spot')}
License Plate: {tx.get('plate')}

Time In:  {tx.get('time_in')}
Time Out: {tx.get('time_out')}

{'-'*50}
Amount Due:     ${tx.get('amount', 0):.2f}
Payment Status: {'PAID' if tx.get('paid') else 'UNPAID'}
{'-'*50}

Comments: {tx.get('comments', 'None')}

{'='*50}
Thank you for your business!
{'='*50}
"""
        
        # Create a window to display and print the invoice
        inv_win = tk.Toplevel(self.root)
        inv_win.title(f'Invoice - Spot {tx.get("spot")} ({tx.get("plate")})')
        inv_win.geometry('550x500')
        
        text_widget = tk.Text(inv_win, font=('Courier', 11), wrap='word')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', invoice_text)
        text_widget.config(state='disabled')
        
        btn_frame = tk.Frame(inv_win)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        def print_to_printer():
            try:
                import subprocess
                import tempfile
                import os
                
                # Write invoice to temp file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(invoice_text)
                    temp_file = f.name
                
                # Print using system default
                if os.name == 'nt':  # Windows
                    os.startfile(temp_file, 'print')
                else:  # Linux/Mac
                    subprocess.run(['lp', temp_file])
                
                messagebox.showinfo('Success', 'Invoice sent to printer')
                inv_win.destroy()
            except Exception as e:
                messagebox.showerror('Print Error', f'Failed to print: {e}')
        
        tk.Button(btn_frame, text='Print', width=12, bg='#4CAF50', fg='white', command=print_to_printer).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Close', width=12, bg='#f44336', fg='white', command=inv_win.destroy).pack(side='left', padx=4)

    def daily_invoice(self):
        """Generate daily invoice showing all payments for today."""
        if not self.park or not self.park.transactions:
            messagebox.showwarning('No data', 'No transactions available')
            return
        
        from datetime import datetime, date
        from datetime import timezone, timedelta
        
        # Get today's date in GMT+7
        tz = timezone(timedelta(hours=7))
        today = datetime.now(tz).date()
        
        # Filter transactions for today
        today_txs = []
        for tx in self.park.transactions:
            try:
                tx_date = datetime.fromisoformat(tx.get('time_out', '')).date()
                if tx_date == today:
                    today_txs.append(tx)
            except Exception:
                pass
        
        # Create invoice window
        inv_win = tk.Toplevel(self.root)
        inv_win.title(f'Daily Invoice - {today.strftime("%Y-%m-%d")}')
        inv_win.geometry('700x500')
        
        # Calculate totals
        total_amount = sum(tx.get('amount', 0) for tx in today_txs)
        paid_amount = sum(tx.get('amount', 0) for tx in today_txs if tx.get('paid'))
        unpaid_amount = total_amount - paid_amount
        
        invoice_header = f"""
{'='*60}
                    DAILY INVOICE
                    {today.strftime('%A, %B %d, %Y')}
{'='*60}

{'Spot':<8}{'Plate':<15}{'Time In':<20}{'Amount':<12}{'Status':<10}
{'-'*60}
"""
        
        invoice_items = ""
        for tx in today_txs:
            status = 'PAID' if tx.get('paid') else 'UNPAID'
            invoice_items += f"{tx.get('spot'):<8}{str(tx.get('plate', '')):<15}{str(tx.get('time_in', ''))[:16]:<20}${tx.get('amount', 0):<11.2f}{status:<10}\n"
        
        invoice_footer = f"""{'-'*60}
{'TOTAL TRANSACTIONS:':<45}{len(today_txs)}
{'Total Amount:':<45}${total_amount:>10.2f}
{'Paid Amount:':<45}${paid_amount:>10.2f}
{'Unpaid Amount:':<45}${unpaid_amount:>10.2f}
{'='*60}
Generated: {datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}
"""
        
        full_invoice = invoice_header + invoice_items + invoice_footer
        
        text_widget = tk.Text(inv_win, font=('Courier', 10), wrap='word')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', full_invoice)
        text_widget.config(state='disabled')
        
        btn_frame = tk.Frame(inv_win)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        def print_to_printer():
            try:
                import subprocess
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(full_invoice)
                    temp_file = f.name
                
                if os.name == 'nt':  # Windows
                    os.startfile(temp_file, 'print')
                else:  # Linux/Mac
                    subprocess.run(['lp', temp_file])
                
                messagebox.showinfo('Success', 'Daily invoice sent to printer')
            except Exception as e:
                messagebox.showerror('Print Error', f'Failed to print: {e}')
        
        tk.Button(btn_frame, text='Print', width=12, bg='#4CAF50', fg='white', command=print_to_printer).pack(side='left', padx=4)
        tk.Button(btn_frame, text='Close', width=12, bg='#f44336', fg='white', command=inv_win.destroy).pack(side='left', padx=4)

    def view_transactions(self):
        # show all transactions in a table view
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return

        win = tk.Toplevel(self.root)
        win.title('Transaction History — Table View')
        win.geometry('800x400')

        cols = ('index', 'spot', 'plate', 'time_in', 'time_out', 'amount', 'paid')
        tree = ttk.Treeview(win, columns=cols, show='headings')
        tree.heading('index', text='#')
        tree.heading('spot', text='Spot')
        tree.heading('plate', text='License Plate')
        tree.heading('time_in', text='Time In (GMT+7)')
        tree.heading('time_out', text='Time Out')
        tree.heading('amount', text='Amount')
        tree.heading('paid', text='Paid')
        tree.column('index', width=40, anchor='center')
        tree.column('spot', width=50, anchor='center')
        tree.column('plate', width=140, anchor='w')
        tree.column('time_in', width=200, anchor='w')
        tree.column('time_out', width=140, anchor='w')
        tree.column('amount', width=80, anchor='e')
        tree.column('paid', width=40, anchor='center')

        vsb = ttk.Scrollbar(win, orient='vertical', command=tree.yview)
        hsb = ttk.Scrollbar(win, orient='horizontal', command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        win.grid_rowconfigure(0, weight=1)
        win.grid_columnconfigure(0, weight=1)

        # populate all transactions in reverse order (newest first)
        for i, tx in enumerate(reversed(self.park.transactions), 1):
            spot = tx.get('spot', '')
            plate = tx.get('plate', '')
            time_in = tx.get('time_in', '')
            time_out = tx.get('time_out', '')
            amount = tx.get('amount', '')
            paid_flag = '✓' if tx.get('paid') else ''
            tree.insert('', 'end', values=(i, spot, plate, time_in, time_out, amount, paid_flag))

        # double-click to edit
        def on_double_click(event):
            item = tree.identify_row(event.y)
            if not item:
                return
            vals = tree.item(item, 'values')
            try:
                idx = int(vals[0]) - 1
                # reverse the index since we displayed newest first
                tx_idx = len(self.park.transactions) - idx - 1
                if 0 <= tx_idx < len(self.park.transactions):
                    tx = self.park.transactions[tx_idx]
                    self.show_transaction_dialog(tx)
            except Exception:
                pass

        tree.bind('<Double-1>', on_double_click)

        btn_frame = tk.Frame(win)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky='e', pady=(8,8), padx=8)
        tk.Button(btn_frame, text='Close', command=win.destroy).pack(side='right')

    def perform_search(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return
        q = self.search_var.get().strip()
        if not q:
            messagebox.showinfo('Search', 'Enter a license plate or spot number to search')
            return

        results = []
        # try treat as spot number
        try:
            spot = int(q)
            rec = self.park.parked_cars.get(spot)
            if rec:
                results.append(f'Parked - Spot {spot}: {rec.get("plate")} (in: {rec.get("time_in")})')
            for tx in self.park.transactions:
                if tx.get('spot') == spot:
                    results.append(f'Transaction - Spot {spot}: {tx.get("plate")} ${tx.get("amount")} paid:{tx.get("paid")}')
        except ValueError:
            # search by plate substring (case-insensitive)
            qlow = q.lower()
            for spot, rec in self.park.parked_cars.items():
                if qlow in rec.get('plate','').lower():
                    results.append(f'Parked - Spot {spot}: {rec.get("plate")} (in: {rec.get("time_in")})')
            for tx in self.park.transactions:
                if qlow in tx.get('plate','').lower():
                    results.append(f'Transaction - Spot {tx.get("spot")} : {tx.get("plate")} ${tx.get("amount")} paid:{tx.get("paid")}')

        # show results
        dlg = tk.Toplevel(self.root)
        dlg.title(f"Search: {q}")
        dlg.geometry('520x260')
        lb = tk.Listbox(dlg, width=80)
        lb.pack(fill='both', expand=True, padx=8, pady=8)
        if not results:
            lb.insert('end', 'No results')
        else:
            for r in results:
                lb.insert('end', r)

        def on_select(event=None):
            sel = lb.curselection()
            if not sel:
                return
            text = lb.get(sel[0])
            # try to parse 'Spot X' to highlight in tree
            if 'Spot' in text:
                try:
                    parts = text.split()
                    idx = parts.index('Spot')
                    spotnum = int(parts[idx+1].strip(':'))
                    # highlight in tree by selecting the row with that spot
                    for item in self.tree.get_children():
                        if self.tree.item(item, 'values')[0] == spotnum:
                            self.tree.selection_set(item)
                            self.tree.see(item)
                            break
                except Exception:
                    pass

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill='x', pady=(0,8))
        tk.Button(btn_frame, text='Select', command=on_select).pack(side='right', padx=8)
        tk.Button(btn_frame, text='Close', command=dlg.destroy).pack(side='right')

    # ------------------------------------------------------------------ User management
    def change_password_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Change Password')
        dlg.geometry('360x260')
        dlg.resizable(False, False)

        title = tk.Label(dlg, text=f'Change Password — {self.current_user}', font=('Arial', 12, 'bold'))
        title.pack(pady=12)

        cur_frame = tk.LabelFrame(dlg, text='Current Password', padx=12, pady=10)
        cur_frame.pack(fill='x', padx=20, pady=6)
        current_var = tk.StringVar()
        current_entry = tk.Entry(cur_frame, textvariable=current_var, show='*', font=('Arial', 11))
        current_entry.pack(fill='x')
        current_entry.focus()

        new_frame = tk.LabelFrame(dlg, text='New Password', padx=12, pady=10)
        new_frame.pack(fill='x', padx=20, pady=6)
        new_var = tk.StringVar()
        new_entry = tk.Entry(new_frame, textvariable=new_var, show='*', font=('Arial', 11))
        new_entry.pack(fill='x')

        confirm_frame = tk.LabelFrame(dlg, text='Confirm New Password', padx=12, pady=10)
        confirm_frame.pack(fill='x', padx=20, pady=6)
        confirm_var = tk.StringVar()
        confirm_entry = tk.Entry(confirm_frame, textvariable=confirm_var, show='*', font=('Arial', 11))
        confirm_entry.pack(fill='x')

        feedback = tk.Label(dlg, text='', fg='red')
        feedback.pack()

        def submit():
            current_pw = current_var.get()
            new_pw = new_var.get()
            confirm_pw = confirm_var.get()

            if not self.user_manager.authenticate(self.current_user, current_pw):
                feedback.config(text='Current password is incorrect.')
                current_var.set('')
                current_entry.focus()
                return
            if not new_pw:
                feedback.config(text='New password cannot be empty.')
                return
            if new_pw != confirm_pw:
                feedback.config(text='Passwords do not match.')
                confirm_var.set('')
                confirm_entry.focus()
                return
            try:
                self.user_manager.change_password(self.current_user, new_pw)
                messagebox.showinfo('Success', 'Password updated successfully.')
                dlg.destroy()
            except ValueError as e:
                feedback.config(text=str(e))

        btn_frame = tk.Frame(dlg)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text='Update', width=12, bg='#4CAF50', fg='white', command=submit).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Cancel', width=12, command=dlg.destroy).pack(side='left', padx=6)

        def on_enter(event):
            submit()

        confirm_entry.bind('<Return>', on_enter)

    def logout(self):
        if messagebox.askyesno('Logout', 'Are you sure you want to logout?'):
            self.on_exit()
            run_gui(self.db_path)

    def manage_users_dialog(self):
        if not self.user_manager.is_admin(self.current_user):
            messagebox.showerror('Access Denied', 'Only admins can manage users.')
            return

        dlg = tk.Toplevel(self.root)
        dlg.title('User Management')
        dlg.geometry('520x420')
        dlg.resizable(False, False)

        columns = ('username', 'role', 'created')
        tree = ttk.Treeview(dlg, columns=columns, show='headings')
        tree.heading('username', text='Username')
        tree.heading('role', text='Role')
        tree.heading('created', text='Created')
        tree.column('username', width=140, anchor='w')
        tree.column('role', width=80, anchor='center')
        tree.column('created', width=220, anchor='w')

        vsb = ttk.Scrollbar(dlg, orient='vertical', command=tree.yview)
        tree.configure(yscroll=vsb.set)

        tree.grid(row=0, column=0, sticky='nsew', padx=(10,0), pady=10)
        vsb.grid(row=0, column=1, sticky='ns', pady=10, padx=(0,10))

        dlg.grid_rowconfigure(0, weight=1)
        dlg.grid_columnconfigure(0, weight=1)

        def refresh_users():
            for item in tree.get_children():
                tree.delete(item)
            for user in self.user_manager.list_users():
                created_display = user.get('created_at', '') or ''
                tree.insert('', 'end', values=(user['username'], user['role'], created_display))

        refresh_users()

        btn_frame = tk.Frame(dlg)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=(0, 12))

        def add_user():
            username = simpledialog.askstring('Add User', 'Enter username:', parent=dlg)
            if not username:
                return
            password = simpledialog.askstring('Add User', 'Enter password:', show='*', parent=dlg)
            if password is None:
                return
            confirm = simpledialog.askstring('Add User', 'Confirm password:', show='*', parent=dlg)
            if confirm is None:
                return
            if password != confirm:
                messagebox.showerror('Error', 'Passwords do not match.', parent=dlg)
                return
            role = simpledialog.askstring('Add User', "Role (admin/user):", initialvalue='user', parent=dlg)
            if role is None:
                role = 'user'
            try:
                self.user_manager.create_user(username.strip(), password, role.strip().lower())
                messagebox.showinfo('Success', f'User "{username}" created.', parent=dlg)
                refresh_users()
            except ValueError as e:
                messagebox.showerror('Error', str(e), parent=dlg)

        def reset_password():
            selection = tree.selection()
            if not selection:
                messagebox.showwarning('Select User', 'Please select a user first.', parent=dlg)
                return
            username = tree.item(selection[0], 'values')[0]
            new_pw = simpledialog.askstring('Reset Password', f'Enter new password for {username}:', show='*', parent=dlg)
            if new_pw is None:
                return
            confirm = simpledialog.askstring('Reset Password', 'Confirm new password:', show='*', parent=dlg)
            if confirm is None:
                return
            if new_pw != confirm:
                messagebox.showerror('Error', 'Passwords do not match.', parent=dlg)
                return
            try:
                self.user_manager.reset_password(username, new_pw)
                messagebox.showinfo('Success', f'Password for "{username}" updated.', parent=dlg)
            except ValueError as e:
                messagebox.showerror('Error', str(e), parent=dlg)

        def delete_user():
            selection = tree.selection()
            if not selection:
                messagebox.showwarning('Select User', 'Please select a user first.', parent=dlg)
                return
            username = tree.item(selection[0], 'values')[0]
            if username == self.current_user:
                messagebox.showerror('Error', 'You cannot delete the currently logged-in account.', parent=dlg)
                return
            if not messagebox.askyesno('Confirm Delete', f'Delete user "{username}"?', parent=dlg):
                return
            try:
                self.user_manager.delete_user(username)
                messagebox.showinfo('Deleted', f'User "{username}" deleted.', parent=dlg)
                refresh_users()
            except ValueError as e:
                messagebox.showerror('Error', str(e), parent=dlg)

        tk.Button(btn_frame, text='Add User', width=14, command=add_user).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Reset Password', width=14, command=reset_password).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Delete User', width=14, command=delete_user).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Close', width=10, command=dlg.destroy).pack(side='left', padx=12)

    def save_park(self):
        if not self.park:
            messagebox.showwarning('No park', 'Create a car park first')
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files','*.json')], initialfile='carpark.json')
        if not path:
            return
        try:
            self.park.save_to_file(path)
        except Exception as e:
            messagebox.showerror('Save error', str(e))

    def load_park(self):
        path = filedialog.askopenfilename(filetypes=[('JSON files','*.json')])
        if not path:
            return
        try:
            self.park = CarPark.load_from_file(path)
            self.capacity_var.set(self.park.capacity)
            # apply loaded rate to UI
            try:
                self.rate_var.set(float(self.park.rate_per_hour))
            except Exception:
                pass
            self.refresh_list()
        except Exception as e:
            messagebox.showerror('Load error', str(e))

    def set_rate(self):
        try:
            r = float(self.rate_var.get())
            if not self.park:
                messagebox.showwarning('No park', 'Create a car park first')
            else:
                self.park.rate_per_hour = r
        except Exception:
            messagebox.showerror('Error', 'Please enter a valid numeric rate')

    def auto_load_on_startup(self):
        """Try to load from database on startup."""
        try:
            self.park = CarPark.load_from_db(self.db_path)
            if self.park:
                self.capacity_var.set(self.park.capacity)
                try:
                    self.rate_var.set(float(self.park.rate_per_hour))
                except Exception:
                    pass
                self.refresh_list()
            else:
                self.create_park()
        except Exception as e:
            self.create_park()

    def on_exit(self):
        """Auto-save to database before exiting."""
        if self.park:
            try:
                self.park.save_to_db(self.db_path)
            except Exception as e:
                print(f'Failed to save to database: {e}')
        self.root.destroy()


def show_login_dialog(user_manager: UserManager):
    """Display login dialog and return the authenticated username or None."""
    try:
        login_root = tk.Tk()
        login_root.title('Login - Car Park Manager')
        login_root.geometry('400x250')
        login_root.resizable(False, False)
        
        # Center the window
        login_root.update_idletasks()
        x = (login_root.winfo_screenwidth() // 2) - (400 // 2)
        y = (login_root.winfo_screenheight() // 2) - (250 // 2)
        login_root.geometry(f'400x250+{x}+{y}')
        
        # Result variable
        login_result = {'user': None}
    except Exception as e:
        # If we can't create the login window, show error and return None
        try:
            error_root = tk.Tk()
            error_root.withdraw()
            messagebox.showerror('Error', f'Failed to create login window:\n{str(e)}')
            error_root.destroy()
        except:
            pass
        return None
    
    # Title
    title = tk.Label(login_root, text='Car Park Manager Login', font=('Arial', 16, 'bold'))
    title.pack(pady=20)
    
    # Username frame
    username_frame = tk.LabelFrame(login_root, text='Username', font=('Arial', 10, 'bold'), padx=12, pady=10)
    username_frame.pack(fill='x', padx=30, pady=10)
    
    username_var = tk.StringVar()
    username_entry = tk.Entry(username_frame, textvariable=username_var, font=('Arial', 11), width=25)
    username_entry.pack(fill='x')
    username_entry.focus()
    
    # Password frame
    password_frame = tk.LabelFrame(login_root, text='Password', font=('Arial', 10, 'bold'), padx=12, pady=10)
    password_frame.pack(fill='x', padx=30, pady=10)
    
    password_var = tk.StringVar()
    password_entry = tk.Entry(password_frame, textvariable=password_var, font=('Arial', 11), width=25, show='*')
    password_entry.pack(fill='x')
    
    # Error label (initially hidden)
    error_label = tk.Label(login_root, text='', font=('Arial', 9), fg='red')
    error_label.pack(pady=5)
    
    def attempt_login():
        username = username_var.get().strip()
        password = password_var.get().strip()
        if not username or not password:
            error_label.config(text='Please enter both username and password.')
            return
        if user_manager.authenticate(username, password):
            login_result['user'] = username
            login_root.destroy()
        else:
            error_label.config(text='Invalid username or password!')
            password_var.set('')
            password_entry.focus()
    
    def on_enter(event):
        attempt_login()
    
    # Bind Enter key to login
    username_entry.bind('<Return>', lambda e: password_entry.focus())
    password_entry.bind('<Return>', on_enter)
    
    # Buttons
    btn_frame = tk.Frame(login_root)
    btn_frame.pack(fill='x', padx=30, pady=15)
    
    tk.Button(btn_frame, text='Login', width=12, bg='#4CAF50', fg='white', 
              font=('Arial', 10, 'bold'), command=attempt_login).pack(side='left', padx=5)
    tk.Button(btn_frame, text='Cancel', width=12, bg='#f44336', fg='white', 
              font=('Arial', 10), command=login_root.destroy).pack(side='left', padx=5)
    
    login_root.mainloop()
    return login_result['user']


def run_gui(db_path='carpark.db'):
    import os
    import sys
    
    # If running as executable, use the directory where the .exe is located
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        application_path = os.path.dirname(sys.executable)
        db_path = os.path.join(application_path, 'carpark.db')
    else:
        # Running as script
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.getcwd(), db_path)
    
    try:
        user_manager = UserManager(db_path)
    except Exception as e:
        # Show error and exit if we can't initialize user manager
        root = tk.Tk()
        root.withdraw()  # Hide main window
        messagebox.showerror('Initialization Error', 
                           f'Failed to initialize user database:\n{str(e)}\n\nPlease check file permissions.')
        root.destroy()
        return
    
    # Show login dialog first
    try:
        username = show_login_dialog(user_manager)
        if not username:
            return
    except Exception as e:
        # Show error if login dialog fails
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror('Login Error', f'Failed to show login dialog:\n{str(e)}')
        root.destroy()
        return
    
    # Login successful, show main application
    try:
        root = tk.Tk()
        app = CarParkGUI(root, user_manager=user_manager, current_user=username)
        root.mainloop()
    except Exception as e:
        # Show error if main app fails
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror('Application Error', f'Failed to start application:\n{str(e)}')
        root.destroy()


if __name__ == '__main__':
    run_gui()

def view_gui():
    run_gui()

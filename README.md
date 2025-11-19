# Car Park Management System - Executable

## Quick Start

The executable `CarParkManager.exe` is located in the `dist` folder and can be run on any Windows system without needing Python installed.

### How to Run

1. Navigate to the `dist` folder
2. Double-click `CarParkManager.exe`
3. The Car Park Manager GUI will launch

### Distribution

You can copy the `CarParkManager.exe` file to any Windows computer and run it directly. The database file (`carpark.db`) will be created in the same directory as the executable.

### Features

- **Park & Remove Cars**: Track vehicles with timestamps (GMT+7 timezone)
- **Transaction History**: View all transactions with amounts and payment status
- **Editable Comments**: Add notes to each parked car (double-click to edit)
- **Database Storage**: All data persists in SQLite database
- **Search**: Find cars by license plate or spot number
- **Invoicing System**:
  - Print individual transaction invoices
  - Generate daily invoices with payment summaries
  - Direct printer support

### System Requirements

- Windows 7 or later
- No additional software needed (Python is bundled in the executable)

### Data Files

The application creates a `carpark.db` file in the same directory. This file contains all your car park data and persists between sessions.

### Troubleshooting

If the executable doesn't run:
1. Ensure Windows Defender hasn't blocked it
2. Check that you have write permissions in the directory
3. Try running as Administrator

---

**Car Park Manager v1.0** - Professional parking lot management system

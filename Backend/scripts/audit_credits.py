#!/usr/bin/env python3
"""
Credit Reconciliation Audit Script

Run nightly via cron / Windows Task Scheduler:
  0 2 * * * cd /app/Backend && python scripts/audit_credits.py

Purpose:
- Detect credit drift from bugs or concurrency issues
- Alert admins to discrepancies > 5 credits
- Generate audit report for accounting
- Required for financial compliance and fraud prevention

The Problem:
- `totalSpent` is a Float (can accumulate rounding errors)
- `credits` is an Int (no decimals)
- Over time, mismatches occur: User paid for 100 credits but balance shows 97

The Solution:
- Verify: sum(CreditTransaction.amount) == User.credits (initial) - User.credits (current)
"""

import asyncio
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from db import db, connect_db, disconnect_db


async def audit_all_users():
    """Audit credit balances for all users."""
    await connect_db()
    
    discrepancies = []
    
    try:
        # Fetch all users with transactions
        users = await db.user.find_many(
            include={"transactions": True}
        )
        
        for user in users:
            # Calculate expected balance from transaction history
            initial_credits = 50  # Default starting balance (from schema.prisma)
            transaction_sum = sum(tx.amount for tx in user.transactions)
            expected_balance = initial_credits + transaction_sum
            
            actual_balance = user.credits
            drift = actual_balance - expected_balance
            
            if abs(drift) > 0:
                discrepancy = {
                    "user_id": user.id,
                    "email": user.email,
                    "expected": expected_balance,
                    "actual": actual_balance,
                    "drift": drift,
                    "transaction_count": len(user.transactions),
                    "severity": "HIGH" if abs(drift) > 5 else "LOW"
                }
                discrepancies.append(discrepancy)
                
                # Alert if drift > 5 credits
                if abs(drift) > 5:
                    print(f"🚨 HIGH DRIFT: {user.email}")
                    print(f"   Expected: {expected_balance}, Actual: {actual_balance}, Drift: {drift}")
                    print(f"   Transactions: {len(user.transactions)}")
        
        # Generate Report
        print(f"\n{'='*60}")
        print(f"Credit Reconciliation Audit - {datetime.now().isoformat()}")
        print(f"{'='*60}")
        print(f"Total Users Audited: {len(users)}")
        print(f"Discrepancies Found: {len(discrepancies)}")
        
        if discrepancies:
            print("\nDiscrepancy Details:")
            for d in discrepancies:
                print(f"  [{d['severity']}] {d['email'][:30]:<30} Drift: {d['drift']:>4} credits ({d['transaction_count']} transactions)")
        else:
            print("✅ All balances reconciled successfully")
        
    except Exception as e:
        print(f"❌ Audit failed: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        await disconnect_db()
    
    return discrepancies


if __name__ == "__main__":
    discrepancies = asyncio.run(audit_all_users())
    
    # Exit with error code if high-severity discrepancies found
    high_severity_count = sum(1 for d in discrepancies if d["severity"] == "HIGH")
    if high_severity_count > 0:
        print(f"\n⚠️  WARNING: {high_severity_count} high-severity discrepancies found!")
        sys.exit(1)
    else:
        sys.exit(0)

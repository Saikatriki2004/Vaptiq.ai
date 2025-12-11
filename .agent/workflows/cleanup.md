---
description: Code refactoring and cleanup workflow for removing dead code and improving quality
---

# Code Cleanup Workflow

Follow these steps strictly when performing code cleanup and refactoring:

---

## Step 1 - Check for Tests

- Search the project for an existing test suite
  - Look in common folders like `tests/`, `__tests__/`, `spec/`, etc.
- If tests exist:
  - Note the framework and structure
- If no tests exist:
  - Write minimal tests for the code you're about to clean
  - Use existing naming and project conventions

---

## Step 2 - Scan for Cleanup Targets

Identify the following issues:

- **Dead code**: unused variables, functions, classes
- **Debug leftovers**: `print`, `console.log`, `pdb`, `debugger`, etc.
- **Redundant imports**: unused or duplicate imports
- **Useless comments**: outdated or restating-the-obvious comments
- **Typos**: obvious typos in names or strings
- **Inconsistent naming**: mixed conventions (camelCase vs snake_case)
- **Poor formatting**: indentation, spacing, line length issues

---

## Step 3 - Remove or Fix

### Remove
- Unused imports and variables
- Debug statements
- Redundant code (duplication, unnecessary default args, etc.)
- Comments that restate code or are outdated

### Fix
- Typos in names or strings (only if safe and clear)
- Inconsistent or misleading naming
- Bad formatting

---

## Step 4 - Refactor for DRY

- Look for repeating blocks or patterns
- Extract into:
  - Functions
  - Helpers
  - Constants
- Only refactor if it makes the code **clearer and shorter**
- Do not over-abstract

---

## Step 5 - Validate the Changes

// turbo
- Run the test suite
- If any tests fail:
  - Fix or revert the broken changes
- If tests were created in Step 1, include them in the run
- Repeat until all tests pass

---

## Step 6 - Keep It Minimal

- ❌ No structural rewrites unless needed
- ❌ No comments or explanation in the output
- ❌ Don't guess behavior or fix logic
- ✅ Only clean, don't add features

---

## Output Rules

- Apply all changes directly to the code
- Format result in a fenced code block (with language identifier)
- Use consistent, idiomatic style for the language
- Don't include any non-code output

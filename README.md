# HeaderHawk

I built HeaderHawk as a small Python project to learn more about HTTP and web security.

It checks a website's HTTP response headers, shows which common security headers are present or missing, and gives a short explanation of what each one does.

## What it checks

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

## Requirements

- Python 3.9 or newer
- Internet access to reach the target

The script uses Python's standard library, so there are no extra packages to install.

## Usage

Run the script from PowerShell, Command Prompt, or a terminal:

```powershell
python headerhawk.py https://example.com
```

You can also set a timeout:

```powershell
python headerhawk.py https://example.com --timeout 15
```

If you leave out `https://`, the script tries HTTPS by default.

## What I'm learning

- How HTTP requests and response headers work
- Common web security headers
- How to write and organize a small Python CLI tool
- How to identify basic web security configuration issues

## Limitations

This is a basic learning project. It checks whether headers exist, but it does not fully validate whether their values are secure. Missing headers do not automatically mean a website is vulnerable, because the right configuration depends on the application.

## Possible improvements

- Add JSON output
- Add tests
- Check header values for common configuration problems
- Create a report that is easier to read

## Responsible use

Only use HeaderHawk on websites you own or have explicit permission to test. Keep testing within the agreed scope.

This project is for learning and authorized security testing.

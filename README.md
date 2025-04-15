
# mikrotik-login-failure-detector

A script that monitors login failures and automatically blacklists IP addresses based on configurable thresholds.

## Features

- Detects failed login attempts on MikroTik routers.
- Blacklists IP addresses that exceed a certain number of failed login attempts.
- Configurable parameters such as time window, failure threshold, and blacklist timeout.
- Automatically updates the MikroTik firewall address list with blacklisted IPs.

## Installation

1. Copy the script to your MikroTik router.
2. Ensure that your router is running RouterOS 7.18.2 or later.
3. Load the script into the router’s script environment.
4. Configure the script’s parameters:
   - `timeWindow`: The time period (in minutes) to monitor login attempts.
   - `warnThreshold`: The number of failed attempts before blacklisting an IP.
   - `addressListName`: The name of the firewall address list to use for blacklisting.
   - `blacklistTimeout`: The timeout duration for blacklisted IPs.

## Usage

Run the script periodically using the RouterOS scheduler to monitor login attempts:

1. Open the MikroTik scheduler.
2. Create a new scheduled task to run the script at desired intervals (e.g., every minute).

```shell
/system scheduler add name="Login Failure Detector" interval=1m on-event="/system script run login_failure_detector"
```

## Configuration Example

```bash
:local timeWindow 20m
:local warnThreshold 3
:local addressListName "blacklist"
:local blacklistTimeout "10m"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

## Acknowledgments

- Thanks to MikroTik for providing RouterOS and allowing custom scripting.

# DNN SAML Provider
The DNN SAML Provider is an Authentication provider for DNN Platform (formerly DotNetNuke) that uses SAML authentication to authenticate users.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features
- Provides single sign-on and single log-out using standard SAML 2.0 protocols.
- Allows you to configure the Identity Provider (IdP) metadata file or metadata URL.
- Offers flexible options for certificate handling and validation.
- Supports both manual and automated provisioning of user accounts.

## Installation
1. Build or download the DNN SAML Provider installation package.
2. Log in to your DNN instance as a Host or SuperUser.
3. Navigate to **Host > Extensions** (or **Settings > Extensions** in newer versions).
4. Click **Install Extension**, then select and upload the SAML Provider package.
5. Follow the installation wizard and verify the provider is installed successfully.

## Configuration
1. Go to **Admin > Extensions** and find **DNN SAML Provider** in the list.
2. Click **Settings** or **Configure** under the provider.
3. Specify the IdP configuration:
   - SAML Metadata URL or file.
   - SSL certificate for signing (if required).
   - SAML endpoints used for authentication and logout.
4. Ensure the provider is set as the primary authentication method if you want to enforce SAML login.

## Usage
- Once configured, users attempting to log in will be redirected to your IdP’s login page.
- After a successful login, they will be redirected back to DNN and automatically authenticated.
- If single log-out is enabled, logging out from DNN will also trigger a log-out request at the IdP.

## Troubleshooting
- Verify that the IdP metadata is correct and the certificate is valid.
- Check DNN logs under **Admin > Event Viewer** for any SAML-related errors.
- If you are using HTTPS, ensure your SSL certificate is properly configured and that the IdP logs indicate a successful login and response.

## Contributing
1. Fork the repository.
2. Create a feature branch.
3. Make your changes and add tests if necessary.
4. Submit a pull request with a clear description of changes.

## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

<p align="center">
  <img src="https://github.com/jwtplus/.github/blob/main/profile/jwt-plus-line.png?raw=true" alt="JWTPlus Logo">
</p>

# JWTPlus - Enterprise ready platform to manage JWT tokens

Let’s be honest—JWT is powerful, but it’s not perfect. If you’ve worked with JWTs, you know the drill: complex setups, manual token revocation, cryptography headaches. And let’s not forget the ever-growing list of security concerns that crop up every time you integrate JWT into a new project. Sound familiar?

Here’s the laundry list we’ve all had to deal with:

- Implementing strong cryptography for signing, verifying, and renewing tokens (because security is never simple).
- Revoking authentication and refresh tokens to stop account abuse (easier said than done).
- Ensuring refresh tokens are used only once (nobody wants a token reuse disaster).
- Panic mode when a private key gets exposed, which means revoking all issued tokens (no one likes those late-night fixes).
- Dealing with key rotation, transitioning old tokens to new ones while keeping your app secure.
- Constantly upgrading JWT libraries in every new project (the struggle is real).
- Trying to integrate JWT into legacy projects without the right libraries (and failing).
- Doing the same security dance over and over again with every new project.
- And, of course, not being able to oversee the number of active login sessions for any given user (how do you manage access without the right visibility?).

JWTs are here to stay, but the process of managing them doesn’t have to be this complicated. **JWTPlus** is the solution that solves all the pain points we’ve just listed and more.

We built **JWTPlus** in-house after facing the same challenges, and now it’s open-source and ready for the world. Say goodbye to those endless manual steps and focus on building your application instead of worrying about JWT management.

## What makes JWTPlus the solution you need?

1. **No Package Installation Needed:** JWTPlus is a microservice that exposes APIs for JWT management, meaning you don’t need to install anything in your project. It integrates with any system, regardless of the language or framework, with ease.
2. **Support for Multiple Projects:** Running several projects? Each one can have its own set of JWT rules, and JWTPlus gives you unique keys for every project to keep things secure.
3. **Multiple Cryptography Algorithms:** Choose from a wide array of cryptographic algorithms `RS256`, `RS338`, `RS512`, `PS256`, `PS338`, `PS512`, `EC256`, `EC338`, `EC512` whatever fits your needs.
4. **Automatic Key Rotation:** Set your preferred rotation time, and JWTPlus will handle the rest, automatically transitioning old tokens to new ones.
5. **Revoke Single Tokens:** Got a rogue token? No problem. Revoke a single auth or refresh token to prevent further misuse without affecting the rest of your app.
6. **Revoke Private Keys:** One call is all it takes to revoke a private key and invalidate every token signed with it keeping your system secure when you need it most.
7. **Manage User Sessions:** Now, you can oversee the number of active login sessions for any user, giving you better control over your application’s security.
8. **High Performance & Scalability:** Designed for high availability, JWTPlus can horizontally scale across multiple servers, ensuring fast, reliable, and efficient JWT management even under heavy workloads.

**JWTPlus** is the answer to the JWT struggle. It simplifies token management and security, letting you focus on what really matters—building your application with confidence and peace of mind.

## Installation Requirements

### Standard Deployment

- **Basic Server Specs** – At least 1 CPU, 1GB RAM, and 5GB of disk space. That’s the bare minimum, but if you’re running a high-traffic app, consider scaling up.

- **A Freshly Installed Linux Server** – Any minimal freshly installed Linux installation works fine, but we recommend Ubuntu 24.04 LTS for the best compatibility.

- **MySQL or MariaDB** – JWTPlus needs a database to store and manage tokens, so make sure you have either MySQL or MariaDB installed.


### Installation Requirements for High Availability (HA)

Need JWTPlus to handle massive workloads without breaking a sweat? Here’s what you need for a high-performance, highly available setup:

- **Cloud Hosting** – Deploy on a reliable cloud provider like AWS, Azure, DigitalOcean, Vultr, or any infrastructure that supports scalable deployments.
- **Load Balancer** – Use a load balancer to distribute incoming traffic across multiple nodes, ensuring smooth performance and zero downtime.
- **Multi-AZ Deployment** – For better availability, set up Multi-AZ (Availability Zones) to keep your services running even if one data center goes down.
- **Auto Scaling** – Handle traffic spikes effortlessly with an Auto Scaling Group, which automatically adds or removes compute resources based on demand.
- **Database Replication** – Deploy multiple database nodes with master-slave replication, ensuring data consistency, failover support, and high availability.

With this setup, JWTPlus can scale dynamically, handle unpredictable traffic, and maintain enterprise-grade reliability without manual intervention.

## Documentation & Contribution

JWTPlus is open-source and community-driven. Feel free to fork, submit pull requests, or discuss new features in the issues section!

📌 **[Read the Docs](https://jwtplus.com/docs)** | 🛠 **[Installation Guide](https://jwtplus.com/docs/install-auto.html)** | 🔥 **[Contribute](https://jwtplus.com/docs/contribute.html)**

## Security Reporting

If you find a **security vulnerability**, please **do not** open a public issue. Instead, email all details to **[hello@jwtplus.com](mailto:hello@jwtplus.com)**.

## Commercial Support

For **enterprise deployments, priority support, or custom integrations**, contact us at **[hello@jwtplus.com](mailto:hello@jwtplus.com)**.


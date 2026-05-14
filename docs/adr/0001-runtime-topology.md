# ADR 0001: Shared codebase with dedicated daemons

Endorium Nexus is organized as one C++20 codebase with multiple deployment units. The API, directory/Kerberos, network, and PKI/APT runtimes share libraries and a common configuration model, but they are shipped as dedicated processes so they can use the correct Linux capabilities, failure domains, and service-level restart policies in production.


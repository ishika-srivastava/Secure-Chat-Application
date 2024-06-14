# Secure Chat Application
## Overview
This project implements a secure chat application in Python, ensuring encrypted communication between clients and a server using RSA for key exchange and AES for message encryption.

## Features
- RSA(Rivest-Shamir-Adleman) for key exchange
- AES(Advanced Encryption Standard) for message encryption
- Multi-threaded server for handling concurrent client connections
- JSON-formatted logging for tracking events

## Technologies Used
- Python
- cryptography library
- socket module
- threading module
- json module
- logging module

## Setup
### Clone the repository:

```
$ git clone https://github.com/ishika-srivastava/Secure-Chat-Application.git
$ cd Secure-Chat-Application
```

### Install dependencies:

```
$ pip install -r requirements.txt 
```

### Run the server:
```
$ python server.py
```

### Run a client:
```
$ python client.py
```

## Usage
- Start the server and connect clients.
- Exchange messages securely using the implemented protocols.
- Commands and features are provided in the client interface.

## Logging
The application logs events such as client connections, messages received, and errors encountered in JSON format. Logs are stored in server.log.

## Notes
- Ensure Python 3.12.0 and the required libraries are installed.
- Customize encryption settings or network configurations as needed.

## Author
Ishika Srivastava</br>
Contact: ishika.srivastava029@gmail.com

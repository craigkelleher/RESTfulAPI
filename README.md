# RestfulAPI

API where the server does not store any state about the client session on the server-side.
Implemented a REST API that uses resource based URLS, pagination, and status codes.
Implemented a system for creating users and for authorization.
* Google Cloud Datastore stores the data utilizing Python and Google App Engine to deploy the project.

# API Specifications Document

https://github.com/craigkelleher/RestfulAPI/blob/main/kelleher_project.pdf

# Functionality

This app will allow the user to create, read, update, and delete operations for all non-user entities.
This application has a Postman Test collection that demonstrates the operations for all non-user entities.

# Frontend

The 'templates' folder contains a web application that can use the API developed in this project.
The front end prompts the user to login, and generates a JSON Web TOken for the user to use in the postman collection for authentication.

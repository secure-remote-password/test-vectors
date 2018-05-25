# SRP-6a test vectors

This repository contains test vectors for validating the SRP-6a protocol implementations.
Test vector is a JSON file that specifies the exact values for each authentication step.

# Using test vectors

* Load a test vector using a suitable JSON implementation for your platform. 
* Initialize your SRP library using `hash`, `N`, and `g` test vector parameters.
* Verify each computation step against the values from the test vector.

# Examples

TODO
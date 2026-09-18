# Schnorr Threshold Signature Scheme (2-of-3)

A C implementation of a Schnorr signature scheme with two participants, enabling a threshold signing protocol where both parties must collaborate to produce a valid signature.

---

## Overview

This project implements a **2-of-3 threshold Schnorr signature scheme**, meaning that a valid signature can only be generated when both participants cooperate. Neither party alone can produce a valid signature, which provides strong security guarantees in distributed or multi-party settings.

The Schnorr signature scheme is renowned for its simplicity, efficiency, and strong security properties (provably secure under the discrete logarithm assumption in the random oracle model). The threshold extension further enhances security by eliminating any single point of failure or trust.

---

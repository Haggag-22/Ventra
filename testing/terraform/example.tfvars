# Copy to terraform.tfvars (or pass with -var-file) and adjust.
# Apply with:  terraform apply -var-file=example.tfvars

# --- master toggles ---------------------------------------------------------
enable_logging   = true
enable_expensive = false

# Detection services (GuardDuty, Security Hub, Macie, Detective, Inspector2) are
# detected automatically — already-enabled ones are skipped. Nothing to set here.

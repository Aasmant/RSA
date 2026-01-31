# Submission Guide

## Step 1: Convert to PDF

### Using Pandoc (Recommended)

```bash
cd /Users/aasmantlaxmikantpatil/Downloads/SS/rsa-encryption-service

# Simple conversion
pandoc SECURITY_REPORT.md -o Software_Security_Assignment.pdf

# With table of contents and formatting
pandoc SECURITY_REPORT.md \
  -o Software_Security_Assignment.pdf \
  --toc \
  --number-sections \
  -V geometry:margin=1in \
  -V fontsize=11pt
```

### Online Tools (No Installation)

1. Visit: https://pandoc.org/try/
2. Copy SECURITY_REPORT.md content
3. Select: Output: PDF via LaTeX
4. Download PDF

### Microsoft Word

1. Copy SECURITY_REPORT.md content
2. Paste into new Word document
3. Format as needed (styles, fonts, spacing)
4. Save as PDF

## Step 2: Verify PDF

Checklist:
- [ ] All 10 sections present
- [ ] Table of contents correct
- [ ] No formatting errors
- [ ] File size reasonable (5-15MB)
- [ ] Readable on screen and printing

```bash
# Check file
ls -lh Software_Security_Assignment.pdf
file Software_Security_Assignment.pdf
```

## Step 3: Git Repository Setup

### Initialize Git

```bash
cd /Users/aasmantlaxmikantpatil/Downloads/SS/rsa-encryption-service

# Initialize repository
git init
git config user.name "Your Name"
git config user.email "your.email@hs-offenburg.de"

# Add all files
git add .
git commit -m "Initial commit: RSA Encryption Service SSDLC Assignment"
```

### Create Remote Repository

#### Option A: EdugGit (HS Offenburg)

1. Go to: https://edugit.hs-offenburg.de
2. Click "New Project"
3. Name: `rsa-encryption-service`
4. Visibility: Private
5. Create project

```bash
# Add remote
git remote add origin https://edugit.hs-offenburg.de/YOUR_USERNAME/rsa-encryption-service.git

# Push
git push -u origin main
```

#### Option B: GitHub

1. Go to: https://github.com/new
2. Name: `rsa-encryption-service`
3. Create repository

```bash
# Add remote
git remote add origin https://github.com/YOUR_USERNAME/rsa-encryption-service.git

# Push
git push -u origin main
```

### Invite Prof. Schaad

**EdugGit**:
1. Go to repository settings
2. Select "Members"
3. Add user: prof.schaad or similar
4. Role: Maintainer

**GitHub**:
1. Go to repository settings
2. Select "Collaborators"
3. Search: Prof. Schaad or schaad@hs-offenburg.de
4. Role: Maintain

## Step 4: Verify Repository

```bash
# Check remote
git remote -v

# Check history
git log --oneline

# View files
git ls-tree -r main
```

## Step 5: Moodle Submission

1. Go to Moodle course: Software Security 2025/26
2. Find assignment: "SSDLC Assignment Submission"
3. Click "Add submission"
4. Upload: `Software_Security_Assignment.pdf`
5. Add comments:
   ```
   Repository: https://edugit.hs-offenburg.de/YOUR_USERNAME/rsa-encryption-service
   (or GitHub link)
   
   Please invite me as maintainer to review the code.
   ```
6. Save and submit

## File Checklist Before Submission

### PDF
- [ ] SECURITY_REPORT.md converted to PDF
- [ ] File size 5-15MB (reasonable range)
- [ ] All 10 sections present
- [ ] Table of contents correct
- [ ] No obvious formatting errors
- [ ] Readable on screen and print
- [ ] Filename: `Software_Security_Assignment.pdf` or similar

### Git Repository
- [ ] Repository initialized with git
- [ ] All files committed (rsa_service.py, requirements.txt, *.md)
- [ ] Remote configured (EdugGit or GitHub)
- [ ] At least one commit with meaningful message
- [ ] Prof. Schaad invited as collaborator
- [ ] Repository accessible

### Code Files
- [ ] rsa_service.py present (350+ lines)
- [ ] requirements.txt present (dependencies listed)
- [ ] No large files (no model weights, large datasets)
- [ ] No secrets/passwords hardcoded (or clearly marked as vulnerable)

### Documentation Files
- [ ] SECURITY_REPORT.md present (20+ pages)
- [ ] THREAT_MODEL.md present
- [ ] README.md present
- [ ] No syntax errors in markdown

## Verification Commands

```bash
# Count lines in code
wc -l rsa_service.py

# List all files
ls -lah

# Verify git history
git log --oneline

# Check file sizes
du -sh *

# Count words in report
wc -w SECURITY_REPORT.md
```

## Common Issues and Solutions

### PDF Conversion Fails

**Error**: "LaTeX Error: Unicode character not set up for use with LaTeX"

**Solution**: 
- Use online Pandoc tool (https://pandoc.org/try/)
- Or use Word for PDF conversion
- Or install BasicTeX: `brew install basictex`

### Git Remote Connection Fails

**Error**: "fatal: could not read Username"

**Solution**:
- Set up SSH keys: https://docs.github.com/en/authentication/connecting-to-github-with-ssh
- Or use HTTPS with personal access token
- Or use EdugGit's web interface for initial setup

### Moodle Upload Fails

**Issue**: File too large or format not accepted

**Solution**:
- Check file size (should be < 50MB)
- Verify PDF format
- Try uploading in different browser
- Check Moodle storage quota

## Due Date Reminder

**Deadline**: February 13, 2026 (Friday)

**Submission Checklist**:
- [ ] PDF uploaded to Moodle
- [ ] Git repository created and accessible
- [ ] Prof. Schaad invited to repository
- [ ] All files present and readable
- [ ] Code properly commented
- [ ] Documentation complete

## Post-Submission

After successful submission:

1. Monitor Moodle for feedback
2. Be prepared to discuss:
   - Security architecture decisions
   - Threat modeling methodology
   - Vulnerability analysis
   - Mitigation strategies
3. Keep repository updated if changes requested
4. Document any feedback for learning

## Support Resources

- **Pandoc Documentation**: https://pandoc.org/MANUAL.html
- **Git Documentation**: https://git-scm.com/book/en/v2
- **EdugGit Help**: https://edugit.hs-offenburg.de/help
- **GitHub Help**: https://docs.github.com/
- **Moodle Help**: Check your institution's Moodle support

---

**Status**: Ready for submission  
**Last Updated**: January 31, 2026  
**Total Files**: 6 core files + generated PDF


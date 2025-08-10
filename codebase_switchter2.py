
import argparse
import subprocess
import zipfile
import shutil
import fnmatch
from pathlib import Path
from datetime import datetime

class CodebaseSwitcher:
    def __init__(self):
        self.states = ['preedit', 'gpt', 'sonnet']
        self.current_dir = Path.cwd()
        self.script_files = ['switch.py']
        self.zip_exclude_patterns = [
            "*.env",           # catch .env and test.env
            "*.zip",           # avoid zipping previous zips
            "*.DS_Store",      # macOS junk
            "*.code",
            "__pycache__",
            "dist", "bin",
            ".venv", "venv",
            "node_modules",
            "target"
        ]

    def should_exclude(self, rel_path: Path):
        # Match both full path and individual segments against patterns
        for pattern in self.zip_exclude_patterns:
            if fnmatch.fnmatch(str(rel_path), pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in rel_path.parts):
                return True
        return False

    def run_git_command(self, args, capture_output=False):
        """Run git command with proper cross-platform handling"""
        try:
            cmd = ['git'] + (args if isinstance(args, list) else args.split())
            result = subprocess.run(cmd, capture_output=capture_output, text=True, 
                                  check=not capture_output, cwd=self.current_dir)
            return result.stdout.strip() if capture_output and result.returncode == 0 else (True if not capture_output else None)
        except FileNotFoundError:
            return False if not capture_output else None
        except subprocess.CalledProcessError as e:
            if not capture_output and e.returncode == 128:
                print(f"❌ Git error: {e.stderr.strip() if e.stderr else 'Repository operation failed'}")
            return False if not capture_output else None
    
    def check_git_available(self):
        """Check if git is available and print helpful error if not"""
        if not shutil.which('git'):
            print("❌ Git not found in PATH.")
            return False
        return True
    
    def get_current_branch(self):
        return self.run_git_command(['branch', '--show-current'], capture_output=True) or "main"
    
    def branch_exists(self, branch):
        result = self.run_git_command(['branch', '--list', branch], capture_output=True)
        return branch in result if result else False
    
    def initialize(self):
        """Initialize git repo with states"""
        if not self.check_git_available():
            return False
            
        if not (self.current_dir / '.git').exists():
            print("🔧 Initializing git repository...")
            if not self.run_git_command(['init']):
                return False
            
            print("🔧 Setting up local git configuration...")
            if not self.run_git_command(['config', '--local', 'user.name', 'Codebase Switcher']):
                print("⚠️  Warning: Could not set local git user.name")
            if not self.run_git_command(['config', '--local', 'user.email', 'switcher@codebase.local']):
                print("⚠️  Warning: Could not set local git user.email")
        
        # Create initial commit if needed
        if not self.run_git_command(['log', '--oneline', '-1'], capture_output=True):
            print("📝 Creating initial commit...")
            try:
                readme_path = self.current_dir / 'README.md'
                readme_path.write_text(
                    f"# Codebase States\n\nProject Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                    encoding='utf-8'
                )
            except (OSError, UnicodeError) as e:
                print(f"⚠️  Warning: Could not create README.md: {e}")
            
            try:
                cursorignore_path = self.current_dir / '.cursorignore'
                switcher_entry = "codebase_switcher2.py"
                
                if cursorignore_path.exists():
                    existing_content = cursorignore_path.read_text(encoding='utf-8')
                    existing_lines = existing_content.strip().split('\n')
                    
                    if switcher_entry not in existing_lines:
                        new_content = existing_content.rstrip() + "\n\n# Ignore codebase switcher script to avoid contaminating AI conversations\n"
                        new_content += switcher_entry + "\n"
                        cursorignore_path.write_text(new_content, encoding='utf-8')
                        print(f"📝 Updated .cursorignore to exclude switcher script: {switcher_entry}")
                    else:
                        print("📝 .cursorignore already excludes switcher script")
                else:
                    cursorignore_path.write_text(
                        "# Ignore codebase switcher script to avoid contaminating AI conversations\n"
                        "codebase_switcher2.py\n",
                        encoding='utf-8'
                    )
                    print("📝 Created .cursorignore to exclude switcher script from AI context")
            except (OSError, UnicodeError) as e:
                print(f"⚠️  Warning: Could not create/update .cursorignore: {e}")
            
            if not self.run_git_command(['add', '.']):
                print("❌ Failed to stage files")
                return False
            if not self.run_git_command(['commit', '-m', 'Initial commit']):
                print("❌ Failed to create initial commit")
                return False
        
        # Auto-commit any existing changes before proceeding
        if self.run_git_command(['status', '--porcelain'], capture_output=True):
            current = self.get_current_branch()
            print(f"💾 Auto-committing changes on {current} before initializing")
            if not self.run_git_command(['add', '.']):
                print("❌ Failed to stage changes")
                return False
            if not self.run_git_command(['commit', '-m', f'Auto-commit on {current} during init']):
                print("❌ Failed to commit changes")
                return False
        
        # Create branches
        if not self.branch_exists('preedit'):
            print("📝 Creating preedit branch")
            if not self.run_git_command(['checkout', '-b', 'preedit']):
                print("❌ Failed to create preedit branch")
                return False
            if self.run_git_command(['status', '--porcelain'], capture_output=True):
                self.run_git_command(['commit', '-m', 'Initialize preedit state'])
        else:
            if not self.run_git_command(['checkout', 'preedit']):
                print("❌ Failed to switch to preedit branch")
                return False
        
        # Create gpt and sonnet branches from preedit
        for state in ['gpt', 'sonnet']:
            if not self.branch_exists(state):
                print(f"📝 Creating {state} branch from preedit")
                if not self.run_git_command(['checkout', '-b', state]):
                    print(f"❌ Failed to create {state} branch")
                    return False
                if not self.run_git_command(['checkout', 'preedit']):
                    print("❌ Failed to return to preedit branch")
                    return False
        
        if not self.run_git_command(['checkout', 'preedit']):
            print("❌ Failed to switch to preedit branch")
            return False
            
        print(f"✅ Initialized with states: {', '.join(self.states)}")
        print("📍 Currently on: preedit")
        return True
    
    def switch_state(self, state):
        """Switch to specified state"""
        if state not in ['gpt', 'sonnet']:
            print(f"❌ Invalid state. Available: gpt, sonnet")
            return False
        
        if not self.check_git_available():
            return False
        
        if not (self.current_dir / '.git').exists():
            print("❌ Not a git repo. Run --init first.")
            return False
        
        if not self.branch_exists(state):
            print(f"❌ State '{state}' doesn't exist. Run --init first.")
            return False
        
        current = self.get_current_branch()
        if current == state:
            print(f"✅ Already on {state}")
            return True
        
        # Handle changes based on transition type
        if self.run_git_command(['status', '--porcelain'], capture_output=True):
            if current == 'preedit' and state == 'gpt':
                # Discard changes when moving from preedit to gpt (preserve original state)
                print(f"🗑️  Discarding changes from {current} to preserve original state")
                if not self.run_git_command(['reset', '--hard']):
                    print("❌ Failed to discard changes")
                    return False
                else:
                    self.run_git_command(['clean', '-fd'])
            else:
                # Auto-commit changes for all other transitions
                print(f"💾 Auto-committing changes from {current} before switching to {state}")
                if not self.run_git_command(['add', '.']):
                    print("❌ Failed to stage changes")
                    return False
                if not self.run_git_command(['commit', '-m', f'Auto-commit from {current} before switching to {state}']):
                    print("❌ Failed to commit changes")
                    return False
                else:
                    self.run_git_command(['clean', '-fd'])
        
        print(f"🔄 Switching to {state}...")
        if self.run_git_command(['checkout', state]):
            print(f"✅ Now on {state}")
            return True
        
        print(f"❌ Failed to switch to {state}")
        return False
    
    def show_status(self):
        """Show current status"""
        if not self.check_git_available():
            return
        
        if not (self.current_dir / '.git').exists():
            print("❌ Not a git repo. Run --init first.")
            return
        
        print(f"📍 Current state: {self.get_current_branch()}")
        print(f"📋 Available: gpt, sonnet")
        print(f"\n🔄 Git status:")
        if not self.run_git_command(['status', '--short']):
            print("No changes")
        print(f"\n📚 Recent commits:")
        if not self.run_git_command(['log', '--oneline', '-3']):
            print("No commits found")
    
    def cleanup_switcher_branches(self):
        """Remove switcher branches, keep files"""
        print("🧹 Cleaning up switcher branches...")
        
        current = self.get_current_branch()
        
        safe_branch = next((b for b in ['main', 'master'] if self.branch_exists(b)), None)
        
        if not safe_branch:
            print("🔄 Creating main branch...")
            if not self.run_git_command(['checkout', '-b', 'main']):
                print("❌ Failed to create main branch")
                return False
        elif current in self.states:
            print(f"🔄 Switching to {safe_branch}...")
            if not self.run_git_command(['checkout', safe_branch]):
                print(f"❌ Failed to switch to {safe_branch}")
                return False
        
        # Delete switcher branches
        for state in self.states:
            if self.branch_exists(state):
                print(f"🗑️  Deleting {state} branch...")
                self.run_git_command(['branch', '-D', state])
        
        print("✅ Cleanup complete - switcher branches removed, files kept")
        return True
    
    def verify_branches_different(self):
        """Verify that preedit, gpt, and sonnet branches are different"""
        print("🔍 Verifying branches are different...")
        
        for state in self.states:
            if not self.branch_exists(state):
                print(f"❌ Branch '{state}' doesn't exist. Run --init first.")
                return False
        
        branch_pairs = [
            ('preedit', 'gpt'),
            ('preedit', 'sonnet'), 
            ('gpt', 'sonnet')
        ]
        
        identical_pairs = []
        for branch1, branch2 in branch_pairs:
            try:
                result = subprocess.run(['git', 'diff', '--quiet', branch1, branch2], 
                                      cwd=self.current_dir, capture_output=True, check=False)
                if result.returncode == 0:
                    identical_pairs.append((branch1, branch2))
            except FileNotFoundError:
                print("❌ Git not found")
                return False
        
        if identical_pairs:
            print("❌ Some branches are identical:")
            for branch1, branch2 in identical_pairs:
                print(f"   - {branch1} and {branch2} have identical content")
            return False
        
        print("✅ All branches are different - proceeding with zip creation")
        return True
    
    def create_zip(self):
        """Create project zip with git structure"""
        if not self.check_git_available():
            return False
        
        if not (self.current_dir / '.git').exists():
            print("❌ Not a git repo. Run --init first.")
            return False
        
        # Auto-commit any changes before creating zip
        if self.run_git_command(['status', '--porcelain'], capture_output=True):
            current = self.get_current_branch()
            print(f"💾 Auto-committing changes on {current} before creating zip")
            if not self.run_git_command(['add', '.']):
                print("❌ Failed to stage changes")
                return False
            if not self.run_git_command(['commit', '-m', f'Auto-commit on {current} before zip creation']):
                print("❌ Failed to commit changes")
                return False
        
        if not self.verify_branches_different():
            return False
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_name = f"codebase_{self.current_dir.name}_{timestamp}.zip"
        zip_path = self.current_dir / zip_name
        
        print(f"📦 Creating {zip_name} with git structure...")
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                exclude_patterns = [
                    "target","node_modules", ".venv", ".env", ".DS_Store", "*.zip",
                    "dist", "bin", "*.code", "__pycache__"
                ]

                for file_path in self.current_dir.rglob('*'):
                    if not file_path.is_file():
                        continue
                    if file_path.name == zip_name or file_path.name in self.script_files:
                        continue

                    rel_path = file_path.relative_to(self.current_dir)
                    rel_str = str(rel_path)

                    # Skip files matching any exclusion pattern
                    if self.should_exclude(rel_path):
                        print(f"⚠️  Excluding from zip: {rel_path}")
                        continue

                    try:
                        arc_path = rel_path.as_posix()
                        zipf.write(file_path, arc_path)
                    except (OSError, ValueError) as e:
                        print(f"⚠️  Skipping {file_path.name}: {e}")
                        continue

            file_size_kb = zip_path.stat().st_size / 1024
            print(f"✅ Created {zip_name} ({file_size_kb:.1f} KB)")
            print("📋 Zip contains: codebase + .git structure")

            self.cleanup_switcher_branches()
            return True
            
        except Exception as e:
            print(f"❌ Error creating zip: {e}")
            if zip_path.exists():
                try:
                    zip_path.unlink()
                    print("🧹 Cleaned up incomplete zip file")
                except OSError:
                    pass
            return False
    
    def reset_to_initial_state(self):
        """Reset codebase to initial state by deleting all switcher branches, with confirmation"""
        print("⚠️  WARNING: Running --reset will delete the gpt and sonnet branches and restore the codebase to its initial state (the state when --init was run).")
        print("💡 Any unsaved work will be lost.")
        print("📦 Use --zip or copy your codebase first if you do not wish to lose unsaved work.")
        confirm = input("❓ Are you sure you want to reset? [y/N]: ").strip().lower()

        if confirm != 'y':
            print("❌ Reset aborted.")
            return False

        if not self.check_git_available():
            return False
        
        if not (self.current_dir / '.git').exists():
            print("❌ Not a git repo. Run --init first.")
            return False
        # Clean up any leftover untracked files
        self.run_git_command(['clean', '-fd'])

        return self.cleanup_switcher_branches()



def main():
    parser = argparse.ArgumentParser(description='Codebase State Switcher')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--init', action='store_true', help='Initialize states')
    group.add_argument('-2', '--gpt', action='store_true', help='Switch to gpt') 
    group.add_argument('-3', '--sonnet', action='store_true', help='Switch to sonnet')
    group.add_argument('-s', '--status', action='store_true', help='Show status')
    group.add_argument('-z', '--zip', action='store_true', help='Create zip')
    group.add_argument('-r', '--reset', action='store_true', help='Reset to initial state (delete all switcher branches)')

    
    args = parser.parse_args()
    switcher = CodebaseSwitcher()
    
    if args.init:
        switcher.initialize()
    elif args.gpt:
        switcher.switch_state('gpt')
    elif args.sonnet:
        switcher.switch_state('sonnet')
    elif args.status:
        switcher.show_status()
    elif args.zip:
        switcher.create_zip()
    elif args.reset:
        switcher.reset_to_initial_state()

if __name__ == '__main__':
    main() 

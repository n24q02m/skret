import sys

with open('internal/syncer/syncer_comprehensive_test.go', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'import (' in line:
        new_lines.append(line)
        new_lines.append('\t"sync"\n')
    elif 'func TestGitHubSyncer_MultipleSecrets_SingleKeyFetch(t *testing.T) {' in line:
        new_lines.append(line)
        new_lines.append('\tvar mu sync.Mutex\n')
    elif 'getKeyCalls++' in line:
        new_lines.append('\t\t\t\tmu.Lock()\n')
        new_lines.append('\t\t\t\tgetKeyCalls++\n')
        new_lines.append('\t\t\t\tmu.Unlock()\n')
    elif 'putCalls++' in line and 'TestGitHubSyncer_MultipleSecrets_SingleKeyFetch' in "".join(new_lines[-50:]):
        new_lines.append('\t\t\t\tmu.Lock()\n')
        new_lines.append('\t\t\t\tputCalls++\n')
        new_lines.append('\t\t\t\tmu.Unlock()\n')
    elif 'func TestGitHubSyncer_EmptySecrets(t *testing.T) {' in line:
        new_lines.append(line)
        new_lines.append('\tvar mu sync.Mutex\n')
    elif 'putCalls++' in line and 'TestGitHubSyncer_EmptySecrets' in "".join(new_lines[-50:]):
        new_lines.append('\t\t\t\tmu.Lock()\n')
        new_lines.append('\t\t\t\tputCalls++\n')
        new_lines.append('\t\t\t\tmu.Unlock()\n')
    else:
        new_lines.append(line)

with open('internal/syncer/syncer_comprehensive_test.go', 'w') as f:
    f.writelines(new_lines)

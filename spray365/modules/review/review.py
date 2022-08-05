from __future__ import annotations

import json

import click

from ..core.auth_result import AuthResult
from ..core.output import console
from ..review.helpers import decode_auth_result_item

auth_results: list[AuthResult] = []


@click.command(
    "review",
    help="View data from password spraying results to identify valid accounts and more",
)
@click.argument("results", type=click.File(mode="r"), required=True)
@click.option("--show_invalid_creds", is_flag=True, default=False, show_default=True)
@click.option("--show_invalid_users", is_flag=True, default=False, show_default=True)
@click.option("--show_valid_aad_access", is_flag=True, default=False, show_default=True)
def command(
    results: click.File,
    show_invalid_creds: bool,
    show_invalid_users: bool,
    show_valid_aad_access: bool,
):
    console.print_info("Reviewing Spray365 results from '%s'" % results.name)

    raw_auth_results = ""
    for line in results:
        raw_auth_results += line

    auth_results: list[AuthResult] = []

    try:
        auth_results = json.loads(raw_auth_results, object_hook=decode_auth_result_item)
    except:
        console.print_error(
            "Unable to read results file '%s'. Perhaps it is formatted incorrectly?"
            % results.name
        )

    valid_users: list[str] = []
    invalid_users: list[str] = []

    valid_creds: list[tuple[str, str]] = []
    valid_creds_aad_details: dict[str, list[str]] = dict()
    partial_valid_auth_results: list[tuple[str, str, str]] = []
    invalid_auth_results: list[tuple[str, str, str]] = []

    for auth_result in auth_results:
        if auth_result.auth_complete_success:
            append_if_not_present(valid_users, auth_result.credential.email_address)
            append_if_not_present(
                valid_creds,
                (auth_result.credential.email_address, auth_result.credential.password),
            )
            if auth_result.credential.endpoint[0] not in valid_creds_aad_details:
                valid_creds_aad_details[auth_result.credential.endpoint[0]] = [
                    auth_result.credential.client_id[0]
                ]
            else:
                if (
                    auth_result.credential.client_id[0]
                    not in valid_creds_aad_details[auth_result.credential.endpoint[0]]
                ):
                    valid_creds_aad_details[auth_result.credential.endpoint[0]].append(
                        auth_result.credential.client_id[0]
                    )

        elif auth_result.auth_partial_success:
            append_if_not_present(valid_users, auth_result.credential.email_address)
            append_if_not_present(
                partial_valid_auth_results,
                (
                    auth_result.credential.email_address,
                    auth_result.credential.password,
                    auth_result.auth_error.message,
                ),
            )
        else:
            if auth_result.auth_error.code != 50034:
                append_if_not_present(valid_users, auth_result.credential.email_address)
            else:
                append_if_not_present(
                    invalid_users, auth_result.credential.email_address
                )
            append_if_not_present(
                invalid_auth_results,
                (
                    auth_result.credential.email_address,
                    auth_result.credential.password,
                    auth_result.auth_error.message,
                ),
            )

    console.print_info("%d authentication attempts" % len(auth_results))

    console.print_info("%d valid user accounts:" % len(valid_users))
    for email_address in valid_users:
        console.print_info("\t%s" % (email_address))

    console.print_info("%d invalid (non-existent) user accounts:" % len(invalid_users))
    if show_invalid_users:
        for email_address in invalid_users:
            console.print_info("\t%s" % (email_address))
    else:
        console.print_info("\tOutput hidden. Show with --show_invalid_users")

    console.print_info("%d valid credentials:" % len(valid_creds))
    for (email_address, password) in valid_creds:
        console.print_info("\t%s / %s" % (email_address, password))

    if show_valid_aad_access:
        console.print_info(
            "%d AAD endpoints are accessible (endpoint / client):"
            % (len(valid_creds_aad_details))
        )
        for (endpoint, client_ids) in valid_creds_aad_details.items():
            console.print_info("\t%s" % (endpoint))
            for client_id in client_ids:
                console.print_info("\t\t%s" % (client_id))

    console.print_info(
        "%d partial-valid credentials (likely due to MFA / Conditional Access Policy):"
        % len(partial_valid_auth_results)
    )
    for (email_address, password, error_message) in partial_valid_auth_results:
        console.print_info("\t%s / %s: %s" % (email_address, password, error_message))

    real_invalid_auth_result_count = sum(
        [1 if t[0] in valid_users else 0 for t in invalid_auth_results]
    )

    console.print_info("%d invalid credentials:" % real_invalid_auth_result_count)
    if show_invalid_creds:
        for (email_address, password, error_message) in invalid_auth_results:
            if email_address in valid_users:
                console.print_info(
                    "\t%s / %s: %s" % (email_address, password, error_message)
                )
    else:
        console.print_info("\tOutput hidden. Show with --show_invalid_creds")


def append_if_not_present(list: list[any], value: any) -> bool:
    if value in list:
        return False
    else:
        list.append(value)
        return True

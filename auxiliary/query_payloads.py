payloads = {
    "cloud_all_last_7_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'Cloud-Issuing',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "cloud_all_more_30_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'Cloud-Issuing',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "cloud_pci_last_7_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'Cloud-Issuing,PCI-DSS-2021',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "cloud_pci_more_30_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'Cloud-Issuing,PCI-DSS-2021',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "data_pci_last_7_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'DBA,PCI-DSS-2021',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "data_pci_more_30_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'DBA,PCI-DSS-2021',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "data_all_last_7_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'DBA',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    },
    "data_all_more_30_days": {
        'action': 'list',
        'severities': '4,5',
        # 'qids': ','.join(qids),
        'use_tags': '1',
        'tag_set_by': 'name',
        'tag_set_include': 'DBA',
        'tag_include_selector': 'all',
        'show_reopened_info': '1',
        'show_igs': '1',
        'truncation_limit': '0',
        'output_format': 'XML'
    }
}

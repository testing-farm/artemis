import dataclasses


@dataclasses.dataclass
class Environment:
    arch: str
    compose: str

    # and maybe more fields in the future, e.g. HW requirements.
    # hw = { 'ram': { 'min': '4GB' }} or something like that

    def __repr__(self):
        # type: () -> str

        return '<Environment: arch={}, compose={}>'.format(
            self.arch,
            self.compose
        )

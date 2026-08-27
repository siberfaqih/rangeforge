from __future__ import annotations

import pytest
from pydantic import ValidationError

from rangeforge.host.models import Architecture, HostInfo, HostOS, RuntimeExecutables
from rangeforge.runtime.guest import (
    GUEST_CAPABILITIES,
    ExecutionLanguage,
    GuestCompatibilityError,
    GuestPlatform,
    GuestRole,
    check_guest_compatibility,
    guest_capabilities,
)
from rangeforge.runtime.models import RuntimeType, VMBackend
from rangeforge.runtime.resolver import VM_HOST_BACKENDS


def _host(
    os: HostOS = HostOS.DARWIN,
    architecture: Architecture = Architecture.ARM64,
) -> HostInfo:
    return HostInfo(
        os=os,
        architecture=architecture,
        apple_silicon=architecture is Architecture.ARM64 and os is HostOS.DARWIN,
        executables=RuntimeExecutables(),
    )


class TestGuestPlatform:
    def test_linux_is_a_known_platform(self) -> None:
        assert GuestPlatform.LINUX.value == "linux"

    def test_windows_is_a_known_platform(self) -> None:
        assert GuestPlatform.WINDOWS.value == "windows"


class TestGuestRole:
    def test_roles_are_typed(self) -> None:
        assert GuestRole.STANDALONE.value == "standalone"
        assert GuestRole.MEMBER_SERVER.value == "member_server"
        assert GuestRole.DOMAIN_CONTROLLER.value == "domain_controller"


class TestExecutionLanguage:
    def test_languages_are_typed(self) -> None:
        assert ExecutionLanguage.SHELL.value == "shell"
        assert ExecutionLanguage.POWERSHELL.value == "powershell"
        assert ExecutionLanguage.PYTHON.value == "python"


class TestGuestCapabilities:
    def test_linux_supports_docker_and_vm(self) -> None:
        caps = guest_capabilities(GuestPlatform.LINUX)
        assert RuntimeType.DOCKER in caps.runtimes
        assert RuntimeType.VM in caps.runtimes

    def test_linux_supports_both_architectures(self) -> None:
        caps = guest_capabilities(GuestPlatform.LINUX)
        assert Architecture.ARM64 in caps.architectures
        assert Architecture.AMD64 in caps.architectures

    def test_linux_has_no_cross_architecture_emulation(self) -> None:
        assert (
            guest_capabilities(GuestPlatform.LINUX).cross_architecture_emulation is False
        )

    def test_windows_capability_matrix(self) -> None:
        """Windows is VM-only, native-architecture-only, standalone-only."""
        caps = guest_capabilities(GuestPlatform.WINDOWS)
        assert caps.runtimes == (RuntimeType.VM,)
        assert caps.architectures == (Architecture.ARM64, Architecture.AMD64)
        assert caps.roles == (GuestRole.STANDALONE,)
        assert caps.execution_languages == (ExecutionLanguage.POWERSHELL,)
        assert caps.cross_architecture_emulation is False

    def test_windows_docker_stays_denied(self) -> None:
        caps = guest_capabilities(GuestPlatform.WINDOWS)
        assert RuntimeType.DOCKER not in caps.runtimes

    def test_windows_server_roles_stay_denied(self) -> None:
        caps = guest_capabilities(GuestPlatform.WINDOWS)
        assert GuestRole.MEMBER_SERVER not in caps.roles
        assert GuestRole.DOMAIN_CONTROLLER not in caps.roles

    def test_windows_shell_and_python_stay_denied(self) -> None:
        """Only built-in PowerShell over UTM/QGA is declared for Windows."""
        caps = guest_capabilities(GuestPlatform.WINDOWS)
        assert ExecutionLanguage.SHELL not in caps.execution_languages
        assert ExecutionLanguage.PYTHON not in caps.execution_languages

    def test_windows_capability_metadata_is_immutable(self) -> None:
        caps = guest_capabilities(GuestPlatform.WINDOWS)
        with pytest.raises(ValidationError):
            caps.runtimes = (RuntimeType.DOCKER,)  # type: ignore[misc]

    def test_windows_capabilities_are_stable_across_lookups(self) -> None:
        first = guest_capabilities(GuestPlatform.WINDOWS)
        second = guest_capabilities(GuestPlatform.WINDOWS)
        assert first == second
        assert first is second

    def test_unknown_platform_raises(self) -> None:
        with pytest.raises(GuestCompatibilityError):
            guest_capabilities("freebsd")  # type: ignore[arg-type]

    def test_capability_registry_is_complete(self) -> None:
        assert set(GUEST_CAPABILITIES) == set(GuestPlatform)

    def test_capability_registry_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            GUEST_CAPABILITIES[GuestPlatform.WINDOWS] = GUEST_CAPABILITIES[  # type: ignore[index]
                GuestPlatform.LINUX
            ]

    def test_vm_host_backend_policy_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            VM_HOST_BACKENDS[  # type: ignore[index]
                (HostOS.LINUX, Architecture.ARM64)
            ] = VMBackend.UTM

    def test_vm_host_backend_policy_cannot_delete_entries(self) -> None:
        with pytest.raises(TypeError):
            del VM_HOST_BACKENDS[(HostOS.DARWIN, Architecture.ARM64)]  # type: ignore[misc]

    def test_vm_host_backend_policy_cannot_clear(self) -> None:
        with pytest.raises((TypeError, AttributeError)):
            VM_HOST_BACKENDS.clear()  # type: ignore[attr-defined]

    def test_vm_host_backend_policy_cannot_update(self) -> None:
        with pytest.raises((TypeError, AttributeError)):
            VM_HOST_BACKENDS.update({(HostOS.LINUX, Architecture.ARM64): VMBackend.UTM})  # type: ignore[attr-defined]

    def test_vm_host_backend_policy_cannot_set_default(self) -> None:
        with pytest.raises((TypeError, AttributeError)):
            VM_HOST_BACKENDS.setdefault(  # type: ignore[attr-defined]
                (HostOS.LINUX, Architecture.ARM64), VMBackend.UTM
            )

    def test_vm_host_backend_policy_contents_are_authoritative(self) -> None:
        assert dict(VM_HOST_BACKENDS) == {
            (HostOS.DARWIN, Architecture.ARM64): VMBackend.UTM,
            (HostOS.DARWIN, Architecture.AMD64): VMBackend.VAGRANT,
            (HostOS.LINUX, Architecture.AMD64): VMBackend.VAGRANT,
            (HostOS.WINDOWS, Architecture.AMD64): VMBackend.VAGRANT,
        }


class TestCheckGuestCompatibilityLinux:
    def test_linux_vm_on_macos_arm64_utm(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert result.compatible
        assert result.platform is GuestPlatform.LINUX
        assert result.errors == ()

    def test_linux_vm_on_amd64_vagrant(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.LINUX, architecture=Architecture.AMD64),
        )
        assert result.compatible

    def test_linux_docker_on_matching_architecture(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.DOCKER,
            backend=None,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert result.compatible

    def test_linux_platform_and_family_are_normalized(self) -> None:
        result = check_guest_compatibility(
            platform=" Linux ",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert result.compatible

    def test_linux_family_with_whitespace_is_normalized(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family=" Linux ",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert result.compatible


class TestCheckGuestCompatibilityBackendPolicy:
    """Backend validity must follow the authoritative resolver host policy."""

    def test_linux_amd64_with_utm_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.LINUX, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert any(
            "'utm' is not valid for host linux/amd64; 'vagrant' is required."
            in error
            for error in result.errors
        )

    def test_macos_arm64_with_vagrant_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert any(
            "'vagrant' is not valid for host darwin/arm64; 'utm' is required."
            in error
            for error in result.errors
        )

    def test_vm_without_backend_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=None,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert any("requires a VM backend" in error for error in result.errors)

    def test_unsupported_vm_host_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.UNSUPPORTED,
            host=_host(os=HostOS.UNSUPPORTED, architecture=Architecture.UNSUPPORTED),
        )
        assert not result.compatible
        assert any(
            "No VM backend is configured" in error for error in result.errors
        )


class TestCheckGuestCompatibilityWindows:
    """Explicit Windows capability matrix: VM-only, native-arch, standalone."""

    def test_windows_vm_arm64_native_on_macos_utm_is_compatible(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert result.compatible
        assert result.platform is GuestPlatform.WINDOWS
        assert result.errors == ()

    def test_windows_vm_on_vagrant_backend_is_denied(self) -> None:
        """Planning-time denial: Windows management is UTM/QGA-only."""
        for host_os in (HostOS.LINUX, HostOS.WINDOWS):
            result = check_guest_compatibility(
                platform="windows",
                family="windows",
                runtime=RuntimeType.VM,
                backend=VMBackend.VAGRANT,
                architecture=Architecture.AMD64,
                host=_host(os=host_os, architecture=Architecture.AMD64),
            )
            assert not result.compatible
            assert any(
                "Windows Vagrant management is unsupported" in error
                for error in result.errors
            )

    def test_windows_vm_utm_is_unaffected_by_the_vagrant_denial(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(os=HostOS.DARWIN, architecture=Architecture.ARM64),
        )
        assert result.compatible
        assert result.errors == ()

    def test_linux_vm_vagrant_is_unaffected_by_the_windows_denial(self) -> None:
        for host_os in (HostOS.LINUX, HostOS.WINDOWS):
            result = check_guest_compatibility(
                platform="linux",
                family="linux",
                runtime=RuntimeType.VM,
                backend=VMBackend.VAGRANT,
                architecture=Architecture.AMD64,
                host=_host(os=host_os, architecture=Architecture.AMD64),
            )
            assert result.compatible
            assert result.errors == ()

    def test_windows_docker_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.DOCKER,
            backend=None,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.WINDOWS, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert result.platform is GuestPlatform.WINDOWS
        assert any("does not support runtime" in error for error in result.errors)

    def test_windows_amd64_guest_on_arm64_host_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.AMD64,
            host=_host(),
        )
        assert not result.compatible
        assert any(
            "silent cross-architecture emulation" in error for error in result.errors
        )

    def test_windows_arm64_guest_on_amd64_host_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.ARM64,
            host=_host(os=HostOS.WINDOWS, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert any(
            "silent cross-architecture emulation" in error for error in result.errors
        )

    def test_windows_cross_architecture_rejection_is_deterministic(self) -> None:
        args: dict[str, object] = {
            "platform": "windows",
            "family": "windows",
            "runtime": RuntimeType.VM,
            "backend": VMBackend.UTM,
            "architecture": Architecture.AMD64,
            "host": _host(),
        }
        first = check_guest_compatibility(**args)  # type: ignore[arg-type]
        second = check_guest_compatibility(**args)  # type: ignore[arg-type]
        assert first == second

    def test_windows_vm_with_wrong_backend_on_arm64_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert any(
            "'vagrant' is not valid for host darwin/arm64; 'utm' is required."
            in error
            for error in result.errors
        )

    def test_windows_vm_with_wrong_backend_on_amd64_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.WINDOWS, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert any(
            "'utm' is not valid for host windows/amd64; 'vagrant' is required."
            in error
            for error in result.errors
        )

    def test_windows_vm_without_backend_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="windows",
            runtime=RuntimeType.VM,
            backend=None,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert any("requires a VM backend" in error for error in result.errors)


class TestCheckGuestCompatibilityArchitecture:
    def test_amd64_guest_on_arm64_host_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.AMD64,
            host=_host(),
        )
        assert not result.compatible
        assert any(
            "silent cross-architecture emulation" in error for error in result.errors
        )

    def test_arm64_guest_on_amd64_host_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.ARM64,
            host=_host(os=HostOS.LINUX, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert any(
            "silent cross-architecture emulation" in error for error in result.errors
        )

    def test_docker_runtime_rejects_mismatched_architecture(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.DOCKER,
            backend=None,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.DARWIN, architecture=Architecture.ARM64),
        )
        assert not result.compatible
        assert any(
            "silent cross-architecture emulation" in error for error in result.errors
        )

    def test_unsupported_guest_architecture_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.UNSUPPORTED,
            host=_host(os=HostOS.UNSUPPORTED, architecture=Architecture.UNSUPPORTED),
        )
        assert not result.compatible
        assert any(
            "does not support guest architecture 'unsupported'" in error
            for error in result.errors
        )


class TestCheckGuestCompatibilityUnknownValues:
    def test_unknown_platform_and_family_are_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="freebsd",
            family="freebsd",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert result.platform is None
        assert result.errors == (
            "Unknown guest platform: 'freebsd'.",
            "Unknown guest family: 'freebsd'.",
        )

    def test_unknown_family_with_known_platform_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="freebsd",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert result.platform is GuestPlatform.LINUX
        assert "Unknown guest family: 'freebsd'." in result.errors

    def test_unknown_platform_with_known_family_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windos",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            architecture=Architecture.AMD64,
            host=_host(os=HostOS.WINDOWS, architecture=Architecture.AMD64),
        )
        assert not result.compatible
        assert result.platform is GuestPlatform.WINDOWS
        assert "Unknown guest platform: 'windos'." in result.errors

    def test_unknown_family_is_deterministic(self) -> None:
        args: dict[str, object] = {
            "platform": "freebsd",
            "family": "freebsd",
            "runtime": RuntimeType.VM,
            "backend": VMBackend.UTM,
            "architecture": Architecture.ARM64,
            "host": _host(),
        }
        first = check_guest_compatibility(**args)  # type: ignore[arg-type]
        second = check_guest_compatibility(**args)  # type: ignore[arg-type]
        assert first == second


class TestCheckGuestCompatibilityPlatformFamilyMismatch:
    """Scenario platform and profile guest family must agree."""

    def test_windows_platform_with_linux_family_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="windows",
            family="linux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert result.platform is GuestPlatform.WINDOWS
        assert any(
            "Guest family 'linux' does not match scenario platform 'windows'"
            in error
            for error in result.errors
        )

    def test_linux_platform_with_windows_family_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="windows",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert result.platform is GuestPlatform.LINUX
        assert any(
            "Guest family 'windows' does not match scenario platform 'linux'"
            in error
            for error in result.errors
        )

    def test_linux_platform_with_typo_family_is_rejected(self) -> None:
        result = check_guest_compatibility(
            platform="linux",
            family="linnux",
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            host=_host(),
        )
        assert not result.compatible
        assert "Unknown guest family: 'linnux'." in result.errors

    def test_mismatch_is_deterministic(self) -> None:
        args: dict[str, object] = {
            "platform": "windows",
            "family": "linux",
            "runtime": RuntimeType.VM,
            "backend": VMBackend.UTM,
            "architecture": Architecture.ARM64,
            "host": _host(),
        }
        first = check_guest_compatibility(**args)  # type: ignore[arg-type]
        second = check_guest_compatibility(**args)  # type: ignore[arg-type]
        assert first == second

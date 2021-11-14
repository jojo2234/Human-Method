package humanmethod;

import java.security.Permission;

/**
 * A factory object that creates Permission objects.
 */

public interface PermissionFactory<T extends Permission> {
    T newPermission(String name);
}
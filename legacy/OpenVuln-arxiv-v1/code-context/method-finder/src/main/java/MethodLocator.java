import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Optional;

public class MethodLocator {
    
    /**
     * Properly escape a string for JSON output
     */
    private static String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    // Control characters (0x00 to 0x1F)
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    } else {
                        escaped.append(c);
                    }
                    break;
            }
        }
        return escaped.toString();
    }
    
    public static void main(String[] args) throws FileNotFoundException {
    if (args.length != 2) {
        System.out.println("Usage: java MethodLocator <source-file> <line-number>");
        return;
    }

    String filePath = args[0];
    int lineNumber = Integer.parseInt(args[1]);

    FileInputStream in = new FileInputStream(filePath);
    CompilationUnit cu = StaticJavaParser.parse(in);

    Optional<MethodDeclaration> result = cu.findAll(MethodDeclaration.class).stream()
            .filter(method -> method.getRange().isPresent()
                    && method.getRange().get().begin.line <= lineNumber
                    && method.getRange().get().end.line >= lineNumber)
            .findFirst();

            if (result.isPresent()) {
            MethodDeclaration method = result.get();
            System.out.println("{");
            System.out.println("  \"found\": true,");
            System.out.println("  \"methodName\": \"" + escapeJson(method.getName().asString()) + "\",");
            System.out.println("  \"startLine\": " + method.getRange().get().begin.line + ",");
            System.out.println("  \"endLine\": " + method.getRange().get().end.line + ",");
            System.out.println("  \"methodSignature\": \"" + escapeJson(method.getDeclarationAsString()) + "\",");
            System.out.println("  \"methodBody\": \"" + escapeJson(method.toString()) + "\"");
            System.out.println("}");
        } else {
            System.out.println("{");
            System.out.println("  \"found\": false,");
            System.out.println("  \"message\": \"No method found at line " + lineNumber + "\"");
            System.out.println("}");
        }
    }
}

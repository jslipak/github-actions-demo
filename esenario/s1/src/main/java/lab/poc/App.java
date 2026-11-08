package lab.poc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class App {
    private static final Logger LOG = LogManager.getLogger(App.class);

    private App() {}

    public static void main(String[] args) {
        LOG.info("Laboratorio de logging iniciado");
    }
}

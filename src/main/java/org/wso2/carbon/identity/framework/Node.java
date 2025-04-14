package org.wso2.carbon.identity.framework;

public class Node {
    private int id;
    private String name;
    private Status status;

    // Constructor
    public Node(int id, String name, Status status) {
        this.id = id;
        this.name = name;
        this.status = status != null ? status : Status.NULL;  // Default to NULL if status is null
    }


    public enum Status {
        SUCCESS,
        FAIL,
        NULL
    }

    // Getters and setters
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }
}
